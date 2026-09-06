// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package cms реализует подписанные сообщения CMS (RFC 5652, он же
// PKCS#7) с отечественными алгоритмами подписи и хэширования.
//
// Это формат файлов .p7s и .sig — открепленных подписей, которыми
// подписывают документы в российском электронном документообороте.
//
// # Что поддерживается
//
//   - разбор и проверка подписанных сообщений, открепленных и со
//     встроенным содержимым;
//   - формирование открепленных и встроенных подписей;
//   - подпись по ГОСТ Р 34.10-2012 с хэшем "Стрибог" 256 и 512 бит;
//   - проверка подписей по устаревшей паре ГОСТ Р 34.10-2001 с
//     ГОСТ Р 34.11-94 — их много в ранее выпущенных документах.
//
// # Чего пакет не делает
//
// Пакет проверяет подпись, но **не строит и не проверяет цепочку
// доверия**: он не обращается к корневым сертификатам, не запрашивает
// списки отзыва и OCSP и не сверяет срок действия сертификата с временем
// подписания. Атрибут времени подписания, если он есть, возвращается как
// есть — это не доверенная метка времени, он подделывается вместе с
// подписью. Всё это ответственность вызывающего кода.
//
// Зашифрованные сообщения (envelopedData) не поддерживаются.
package cms

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/legacy/gost341194"
)

var (
	// ErrMalformed возвращается при некорректной структуре сообщения.
	ErrMalformed = errors.New("cms: некорректная структура сообщения")
	// ErrUnsupported возвращается для неизвестного алгоритма или типа
	// содержимого.
	ErrUnsupported = errors.New("cms: неподдерживаемый алгоритм или тип содержимого")
	// ErrNoCertificate возвращается, если сертификат подписанта не найден
	// в контейнере.
	ErrNoCertificate = errors.New("cms: сертификат подписанта не найден")
	// ErrDigestMismatch возвращается, если хэш содержимого не совпал со
	// значением в подписанных атрибутах: подписан другой файл либо файл
	// изменён.
	ErrDigestMismatch = errors.New("cms: хэш содержимого не совпал с подписанным")
	// ErrSignature возвращается, если подпись не прошла проверку.
	ErrSignature = errors.New("cms: подпись не прошла проверку")
	// ErrNoContent возвращается, если содержимого нет ни во внешнем
	// файле, ни внутри сообщения.
	ErrNoContent = errors.New("cms: содержимое не передано и не встроено")
)

// Идентификаторы из PKCS#9 и PKCS#7.
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// --- структуры ASN.1 (RFC 5652) --------------------------------------------

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type signedDataASN1 struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// --- разбор ----------------------------------------------------------------

// SignedData — разобранное подписанное сообщение.
type SignedData struct {
	// Detached сообщает, что содержимое не встроено и должно быть
	// передано в Verify отдельно.
	Detached bool
	// Content — встроенное содержимое; для открепленной подписи пусто.
	Content []byte
	// ContentType — тип подписанного содержимого. Обычно это id-data,
	// но подписанное сообщение переносит и другие данные: например,
	// токен метки времени несёт id-ct-TSTInfo.
	ContentType asn1.ObjectIdentifier
	// Certificates — сертификаты, вложенные в сообщение. Проверка цепочки
	// доверия остаётся за вызывающим кодом.
	Certificates []*x509.Certificate
	// Signers — подписанты.
	Signers []*Signer

	raw signedDataASN1
}

// Signer — один подписант сообщения.
type Signer struct {
	// Certificate — сертификат подписанта, если он нашёлся в контейнере.
	Certificate *x509.Certificate
	// DigestAlgorithm — идентификатор хэш-функции.
	DigestAlgorithm asn1.ObjectIdentifier
	// SignatureAlgorithm — идентификатор алгоритма подписи.
	SignatureAlgorithm asn1.ObjectIdentifier
	// SigningTime — время из подписанного атрибута. Это НЕ доверенная
	// метка времени: значение подделывается вместе с подписью.
	SigningTime time.Time
	// HasSigningTime сообщает, присутствовал ли атрибут времени.
	HasSigningTime bool
	// HasSigningCertificate сообщает, что подпись несёт ссылку на
	// сертификат подписанта, как того требует профиль CAdES-BES.
	// Проверяется она при проверке подписи.
	HasSigningCertificate bool

	info *signerInfo
}

// Parse разбирает подписанное сообщение CMS в кодировке DER.
func Parse(der []byte) (*SignedData, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, ErrUnsupported
	}

	var raw signedDataASN1
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &raw); err != nil {
		return nil, ErrMalformed
	}

	sd := &SignedData{raw: raw, ContentType: raw.EncapContentInfo.EContentType}

	// Открепленной подпись делает отсутствие поля eContent, а не пустое
	// содержимое: подписать пустой документ тоже можно.
	sd.Detached = len(raw.EncapContentInfo.EContent.FullBytes) == 0
	if !sd.Detached {
		// Встроенное содержимое лежит в OCTET STRING внутри [0].
		var content []byte
		if _, err := asn1.Unmarshal(raw.EncapContentInfo.EContent.Bytes, &content); err != nil {
			return nil, ErrMalformed
		}
		sd.Content = content
	}

	if len(raw.Certificates.Bytes) > 0 {
		elems, err := derElements(raw.Certificates.Bytes)
		if err != nil {
			return nil, ErrMalformed
		}
		for _, e := range elems {
			// Сертификаты с неизвестными crypto/x509 алгоритмами
			// разбираются структурно; ключ достаётся отдельно.
			c, err := x509.ParseCertificate(e)
			if err != nil {
				continue
			}
			sd.Certificates = append(sd.Certificates, c)
		}
	}

	for i := range raw.SignerInfos {
		s, err := newSigner(&raw.SignerInfos[i], sd.Certificates)
		if err != nil {
			return nil, err
		}
		sd.Signers = append(sd.Signers, s)
	}
	if len(sd.Signers) == 0 {
		return nil, ErrMalformed
	}
	return sd, nil
}

func newSigner(si *signerInfo, certs []*x509.Certificate) (*Signer, error) {
	s := &Signer{
		DigestAlgorithm:    si.DigestAlgorithm.Algorithm,
		SignatureAlgorithm: si.SignatureAlgorithm.Algorithm,
		info:               si,
	}
	s.Certificate = findCertificate(si, certs)

	if len(si.SignedAttrs.FullBytes) > 0 {
		attrs, err := parseAttributes(si.SignedAttrs)
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			switch {
			case a.Type.Equal(oidSigningTime):
				var t time.Time
				if _, err := asn1.Unmarshal(a.Values.Bytes, &t); err == nil {
					s.SigningTime, s.HasSigningTime = t, true
				}
			case a.Type.Equal(oidSigningCertificateV2), a.Type.Equal(oidSigningCertificate):
				s.HasSigningCertificate = true
			}
		}
	}
	return s, nil
}

// findCertificate сопоставляет подписанта с сертификатом по
// issuerAndSerialNumber или по subjectKeyIdentifier.
func findCertificate(si *signerInfo, certs []*x509.Certificate) *x509.Certificate {
	if si.SID.Class == asn1.ClassUniversal && si.SID.Tag == asn1.TagSequence {
		var ias issuerAndSerial
		if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err == nil {
			for _, c := range certs {
				if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) &&
					c.SerialNumber.Cmp(ias.Serial) == 0 {
					return c
				}
			}
		}
	}
	if si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0 {
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, si.SID.Bytes) {
				return c
			}
		}
	}
	if len(certs) == 1 {
		return certs[0]
	}
	return nil
}

func parseAttributes(raw asn1.RawValue) ([]attribute, error) {
	elems, err := derElements(raw.Bytes)
	if err != nil {
		return nil, ErrMalformed
	}
	attrs := make([]attribute, 0, len(elems))
	for _, e := range elems {
		var a attribute
		if _, err := asn1.Unmarshal(e, &a); err != nil {
			return nil, ErrMalformed
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// derElements разбивает буфер на последовательность элементов DER.
func derElements(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, ErrMalformed
		}
		i := 1
		n := int(b[i])
		i++
		if n&0x80 != 0 {
			c := n & 0x7f
			if c == 0 || c > 3 || len(b) < i+c {
				return nil, ErrMalformed
			}
			n = 0
			for j := 0; j < c; j++ {
				n = n<<8 | int(b[i+j])
			}
			i += c
		}
		if len(b) < i+n {
			return nil, ErrMalformed
		}
		out = append(out, b[:i+n])
		b = b[i+n:]
	}
	return out, nil
}

// --- проверка --------------------------------------------------------------

// digest вычисляет хэш в соответствии с идентификатором алгоритма.
//
// Для ГОСТ Р 34.11-94 набор подстановок берётся из параметров
// идентификатора; при их отсутствии подразумевается набор CryptoPro,
// который и встречается на практике.
func digest(alg algorithmIdentifier, data []byte) ([]byte, error) {
	switch {
	case alg.Algorithm.Equal(gostasn1.OIDDigest256):
		d := streebog.Sum256(data)
		return d[:], nil
	case alg.Algorithm.Equal(gostasn1.OIDDigest512):
		d := streebog.Sum512(data)
		return d[:], nil
	case alg.Algorithm.Equal(gostasn1.OIDDigest94):
		h := gost341194.NewCryptoPro()
		if len(alg.Parameters.FullBytes) > 0 {
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &oid); err == nil {
				switch {
				case oid.Equal(gostasn1.OIDHashParamTest):
					h = gost341194.NewTest()
				case oid.Equal(gostasn1.OIDHashParamCryptoPro):
				default:
					return nil, ErrUnsupported
				}
			}
		}
		h.Write(data)
		return h.Sum(nil), nil
	}
	return nil, ErrUnsupported
}

// Verify проверяет подписи всех подписантов над содержимым.
//
// Для открепленной подписи content — внешние данные; для встроенной
// передайте nil, будет использовано содержимое сообщения.
//
// Успешная проверка означает только математическую корректность подписи.
// Доверие к сертификату, его срок действия и отзыв проверяются отдельно.
func (sd *SignedData) Verify(content []byte) error {
	for _, s := range sd.Signers {
		if err := sd.VerifySigner(s, content); err != nil {
			return err
		}
	}
	return nil
}

// VerifySigner проверяет подпись одного подписанта.
func (sd *SignedData) VerifySigner(s *Signer, content []byte) error {
	if content == nil {
		if sd.Detached {
			return ErrNoContent
		}
		content = sd.Content
	}
	if s.Certificate == nil {
		return ErrNoCertificate
	}

	pub, err := gostasn1.PublicKeyFromCertificate(s.Certificate)
	if err != nil {
		return err
	}
	sig, err := gostasn1.SignatureFromPKIX(s.info.Signature)
	if err != nil {
		return ErrMalformed
	}
	if len(sig) != 2*pub.Curve.Size() {
		return ErrMalformed
	}

	contentDigest, err := digest(s.info.DigestAlgorithm, content)
	if err != nil {
		return err
	}

	// Без подписанных атрибутов подпись стоит прямо под содержимым.
	if len(s.info.SignedAttrs.FullBytes) == 0 {
		if !gost3410.Verify(pub, contentDigest, sig) {
			return ErrSignature
		}
		return nil
	}

	// С атрибутами: сначала сверяем messageDigest с хэшем содержимого,
	// затем проверяем подпись над самими атрибутами.
	attrs, err := parseAttributes(s.info.SignedAttrs)
	if err != nil {
		return err
	}
	var md []byte
	for _, a := range attrs {
		if a.Type.Equal(oidMessageDigest) {
			var v []byte
			if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err == nil {
				md = v
			}
		}
	}
	if md == nil {
		return ErrMalformed
	}
	if subtle.ConstantTimeCompare(md, contentDigest) != 1 {
		return ErrDigestMismatch
	}

	// Подпись вычисляется над представлением атрибутов с тегом SET,
	// а не с неявным тегом [0] (RFC 5652, п. 5.4).
	signed := append([]byte(nil), s.info.SignedAttrs.FullBytes...)
	signed[0] = 0x31
	attrDigest, err := digest(s.info.DigestAlgorithm, signed)
	if err != nil {
		return err
	}
	if !gost3410.Verify(pub, attrDigest, sig) {
		return ErrSignature
	}

	// Подпись сошлась. Остаётся убедиться, что она относится именно к
	// этому сертификату: идентификатор подписанта в SignerInfo подписью
	// не покрыт, эту роль выполняет signingCertificateV2 (RFC 5035).
	if _, err := checkSigningCertificate(attrs, s.Certificate); err != nil {
		return err
	}
	return nil
}
