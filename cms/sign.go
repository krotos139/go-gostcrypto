// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
)

// ErrKeyMismatch возвращается, если открытый ключ сертификата не
// соответствует переданному секретному ключу.
var ErrKeyMismatch = errors.New("cms: сертификат не соответствует ключу подписи")

// SignOptions настраивает формирование подписи.
type SignOptions struct {
	// Detached — не встраивать подписываемое содержимое в сообщение.
	// Так устроены файлы .p7s и .sig, лежащие рядом с документом.
	Detached bool
	// SigningTime добавляется подписанным атрибутом. Нулевое значение —
	// атрибут не добавляется.
	//
	// Это заявление подписанта, а не доверенная метка времени: значение
	// подделывается вместе со всей подписью.
	SigningTime time.Time
	// Certificates — дополнительные сертификаты, вкладываемые в
	// сообщение, например промежуточные удостоверяющие центры.
	Certificates []*x509.Certificate
	// ContentType задаёт тип подписанного содержимого. Нулевое значение
	// означает id-data — обычный документ. Другие значения нужны, когда
	// подписывается служебная структура: например, токен метки времени
	// несёт id-ct-TSTInfo.
	ContentType asn1.ObjectIdentifier
	// Timestamp получает токен метки времени на значение подписи и
	// кладёт его в неподписанные атрибуты — это профиль CAdES-T.
	// Полученный токен проверяется перед вставкой.
	//
	// Библиотека сама в сеть не ходит: обращение к службе штампов
	// времени пишется вызывающим кодом.
	Timestamp Timestamper
	// NoSigningCertificate убирает подписанный атрибут
	// signingCertificateV2. По умолчанию он добавляется: без него
	// подпись не соответствует профилю CAdES-BES, а идентификатор
	// сертификата в SignerInfo остаётся не покрытым подписью.
	NoSigningCertificate bool
}

// derLen дописывает длину в кодировке DER.
func derLen(out []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(out, byte(n))
	case n < 0x100:
		return append(out, 0x81, byte(n))
	case n < 0x10000:
		return append(out, 0x82, byte(n>>8), byte(n))
	case n < 0x1000000:
		return append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// derWrap заворачивает содержимое в элемент DER с заданным тегом.
func derWrap(tag byte, body []byte) []byte {
	out := derLen([]byte{tag}, len(body))
	return append(out, body...)
}

// derSet собирает SET OF: по правилам DER элементы идут в порядке
// возрастания своих кодировок (X.690, п. 11.6).
func derSet(tag byte, elems [][]byte) []byte {
	sorted := make([][]byte, len(elems))
	copy(sorted, elems)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})
	var body []byte
	for _, e := range sorted {
		body = append(body, e...)
	}
	return derWrap(tag, body)
}

// marshalAttribute кодирует один атрибут с единственным значением.
func marshalAttribute(oid asn1.ObjectIdentifier, value interface{}) ([]byte, error) {
	v, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(attribute{
		Type:   oid,
		Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v},
	})
}

// digestOIDForCurve возвращает идентификатор хэш-функции, парной ключу.
func digestOIDForCurve(c *gost3410.Curve) asn1.ObjectIdentifier {
	if c.Size() > 32 {
		return gostasn1.OIDDigest512
	}
	return gostasn1.OIDDigest256
}

// Sign формирует подписанное сообщение CMS.
//
// Подпись ставится по ГОСТ Р 34.10-2012 со "Стрибогом" той разрядности,
// которая соответствует кривой ключа. В сообщение всегда добавляются
// подписанные атрибуты contentType и messageDigest, как требует RFC 5652,
// п. 5.3 для содержимого типа id-data.
func Sign(rand io.Reader, content []byte, cert *x509.Certificate, priv *gost3410.PrivateKey, opts *SignOptions) ([]byte, error) {
	if opts == nil {
		opts = &SignOptions{}
	}
	if cert == nil || priv == nil {
		return nil, ErrMalformed
	}

	// Сертификат должен соответствовать ключу, иначе получится подпись,
	// которую никто не проверит.
	certPub, err := gostasn1.PublicKeyFromCertificate(cert)
	if err != nil {
		return nil, err
	}
	if !certPub.Equal(&priv.PublicKey) {
		return nil, ErrKeyMismatch
	}

	curve := priv.Curve
	digestOID := digestOIDForCurve(curve)
	digestAlg := algorithmIdentifier{Algorithm: digestOID}
	digestAlgDER, err := asn1.Marshal(digestAlg)
	if err != nil {
		return nil, err
	}

	contentType := opts.ContentType
	if contentType == nil {
		contentType = oidData
	}

	// Подписанные атрибуты.
	contentDigest := gostasn1.DigestForCurve(curve, content)
	attrs := make([][]byte, 0, 4)
	a, err := marshalAttribute(oidContentType, contentType)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, a)
	if a, err = marshalAttribute(oidMessageDigest, contentDigest); err != nil {
		return nil, err
	}
	attrs = append(attrs, a)
	if !opts.SigningTime.IsZero() {
		if a, err = marshalAttribute(oidSigningTime, opts.SigningTime.UTC()); err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}
	if !opts.NoSigningCertificate {
		if a, err = marshalSigningCertificateV2(cert, digestOID); err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}

	// Подпись вычисляется над представлением с тегом SET, а в сообщение
	// атрибуты попадают с неявным тегом [0] (RFC 5652, п. 5.4).
	signedAttrs := derSet(0x31, attrs)
	sig, err := gost3410.Sign(rand, priv, gostasn1.DigestForCurve(curve, signedAttrs))
	if err != nil {
		return nil, err
	}
	sigPKIX, err := gostasn1.SignatureToPKIX(sig)
	if err != nil {
		return nil, err
	}
	implicitAttrs := append([]byte(nil), signedAttrs...)
	implicitAttrs[0] = 0xA0

	sid, err := asn1.Marshal(issuerAndSerial{
		Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
		Serial: cert.SerialNumber,
	})
	if err != nil {
		return nil, err
	}

	si := signerInfo{
		Version:            1, // issuerAndSerialNumber
		SID:                asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    digestAlg,
		SignedAttrs:        asn1.RawValue{FullBytes: implicitAttrs},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: gostasn1.SignatureAlgorithmOID(curve)},
		Signature:          sigPKIX,
	}

	// Метка времени ставится на значение подписи и попадает в
	// неподписанные атрибуты: подписью она не покрыта и покрыта быть не
	// может - она появляется уже после того, как подпись вычислена.
	if opts.Timestamp != nil {
		token, err := requestTimestamp(opts.Timestamp, sigPKIX)
		if err != nil {
			return nil, err
		}
		attr, err := marshalTimestampAttribute(token)
		if err != nil {
			return nil, err
		}
		si.UnsignedAttrs = asn1.RawValue{FullBytes: derSet(0xA1, [][]byte{attr})}
	}
	siDER, err := asn1.Marshal(si)
	if err != nil {
		return nil, err
	}

	// Сертификаты: сначала подписанта, затем переданные дополнительно.
	certDERs := [][]byte{cert.Raw}
	for _, c := range opts.Certificates {
		if !bytes.Equal(c.Raw, cert.Raw) {
			certDERs = append(certDERs, c.Raw)
		}
	}
	certsField := derSet(0xA0, certDERs)

	// encapContentInfo.
	encap := []byte{}
	eContentType, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}
	encap = append(encap, eContentType...)
	if !opts.Detached {
		octets, err := asn1.Marshal(content)
		if err != nil {
			return nil, err
		}
		encap = append(encap, derWrap(0xA0, octets)...)
	}

	var body []byte
	version, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}
	body = append(body, version...)
	body = append(body, derSet(0x31, [][]byte{digestAlgDER})...)
	body = append(body, derWrap(0x30, encap)...)
	body = append(body, certsField...)
	body = append(body, derSet(0x31, [][]byte{siDER})...)

	sd := derWrap(0x30, body)

	ciType, err := asn1.Marshal(oidSignedData)
	if err != nil {
		return nil, err
	}
	ci := append([]byte(nil), ciType...)
	ci = append(ci, derWrap(0xA0, sd)...)
	return derWrap(0x30, ci), nil
}
