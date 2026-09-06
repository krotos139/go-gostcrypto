// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/legacy/gost341194"
)

// Атрибут ссылки на сертификат подписанта (RFC 5035).
//
// Идентификатор подписанта в SignerInfo подписью не покрыт: он лежит вне
// подписанных атрибутов. Атрибут signingCertificateV2 закрывает этот
// зазор — он содержит хэш сертификата и попадает под подпись, связывая
// подпись с конкретным сертификатом. Профиль CAdES-BES требует его
// наличия, и российские средства подписи его выставляют.
var (
	// oidSigningCertificateV2 — id-aa-signingCertificateV2 (RFC 5035).
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	// oidSigningCertificate — устаревший вариант на SHA-1 (RFC 2634).
	oidSigningCertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

var (
	// ErrSigningCertificate возвращается, если атрибут ссылки на
	// сертификат не соответствует сертификату подписанта: подпись
	// перенесена к чужому сертификату либо контейнер собран неверно.
	ErrSigningCertificate = errors.New("cms: атрибут signingCertificate не соответствует сертификату подписанта")
)

type essCertIDv2 struct {
	HashAlgorithm algorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

type essCertID struct {
	CertHash     []byte
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type signingCertificateV1 struct {
	Certs    []essCertID
	Policies asn1.RawValue `asn1:"optional"`
}

// issuerAndSerialFromGN разбирает IssuerSerial: издатель хранится как
// GeneralNames, то есть последовательность с единственным элементом
// directoryName в неявном теге [4].
type issuerSerialASN1 struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// essDigest считает хэш сертификата. Помимо отечественных алгоритмов
// поддерживаются SHA-256 (значение по умолчанию в RFC 5035) и SHA-1
// (устаревший вариант атрибута).
func essDigest(alg algorithmIdentifier, data []byte) ([]byte, error) {
	// Опущенный AlgorithmIdentifier означает SHA-256.
	if len(alg.Algorithm) == 0 || alg.Algorithm.Equal(oidSHA256) {
		d := sha256.Sum256(data)
		return d[:], nil
	}
	if alg.Algorithm.Equal(oidSHA1) {
		d := sha1.Sum(data)
		return d[:], nil
	}
	return digest(alg, data)
}

// checkIssuerSerial сверяет издателя и серийный номер, если они указаны.
//
// Издатель приходит завёрнутым в GeneralNames; сравнение идёт по
// закодированному представлению имени, чтобы не зависеть от того, как
// разобраны отдельные атрибуты имени.
func checkIssuerSerial(raw asn1.RawValue, cert *x509.Certificate) bool {
	if len(raw.FullBytes) == 0 {
		return true // поле необязательное
	}
	var is issuerSerialASN1
	if _, err := asn1.Unmarshal(raw.FullBytes, &is); err != nil {
		return false
	}
	if is.Serial == nil || cert.SerialNumber.Cmp(is.Serial) != 0 {
		return false
	}
	// GeneralNames — последовательность; ищем directoryName в теге [4].
	elems, err := derElements(is.Issuer.Bytes)
	if err != nil {
		return false
	}
	for _, e := range elems {
		var gn asn1.RawValue
		if _, err := asn1.Unmarshal(e, &gn); err != nil {
			continue
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 4 {
			continue
		}
		// directoryName сам по себе — это Name, то есть RDNSequence.
		if bytesEqual(gn.Bytes, cert.RawIssuer) {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// checkSigningCertificate проверяет атрибут ссылки на сертификат.
//
// Возвращает признак того, что атрибут присутствовал, и ошибку, если он
// присутствовал и не сошёлся. RFC 5035 требует считать подпись
// недействительной при расхождении хэша.
func checkSigningCertificate(attrs []attribute, cert *x509.Certificate) (present bool, err error) {
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidSigningCertificateV2):
			var sc signingCertificateV2
			if _, err := asn1.Unmarshal(a.Values.Bytes, &sc); err != nil {
				return true, ErrMalformed
			}
			if len(sc.Certs) == 0 {
				return true, ErrMalformed
			}
			// Первым обязан идти сертификат, которым проверяется подпись.
			id := sc.Certs[0]
			want, err := essDigest(id.HashAlgorithm, cert.Raw)
			if err != nil {
				return true, err
			}
			if !bytesEqual(want, id.CertHash) {
				return true, ErrSigningCertificate
			}
			if !checkIssuerSerial(id.IssuerSerial, cert) {
				return true, ErrSigningCertificate
			}
			return true, nil

		case a.Type.Equal(oidSigningCertificate):
			var sc signingCertificateV1
			if _, err := asn1.Unmarshal(a.Values.Bytes, &sc); err != nil {
				return true, ErrMalformed
			}
			if len(sc.Certs) == 0 {
				return true, ErrMalformed
			}
			id := sc.Certs[0]
			d := sha1.Sum(cert.Raw)
			if !bytesEqual(d[:], id.CertHash) {
				return true, ErrSigningCertificate
			}
			if !checkIssuerSerial(id.IssuerSerial, cert) {
				return true, ErrSigningCertificate
			}
			return true, nil
		}
	}
	return false, nil
}

// marshalSigningCertificateV2 собирает атрибут для подписи сертификатом
// cert. Хэш берётся тот же, которым подписывается сообщение.
func marshalSigningCertificateV2(cert *x509.Certificate, digestOID asn1.ObjectIdentifier) ([]byte, error) {
	var certHash []byte
	switch {
	case digestOID.Equal(gostasn1.OIDDigest256):
		d := streebog.Sum256(cert.Raw)
		certHash = d[:]
	case digestOID.Equal(gostasn1.OIDDigest512):
		d := streebog.Sum512(cert.Raw)
		certHash = d[:]
	case digestOID.Equal(gostasn1.OIDDigest94):
		d := gost341194.Sum256(cert.Raw)
		certHash = d[:]
	default:
		return nil, ErrUnsupported
	}

	// Издатель кодируется как GeneralNames с единственным directoryName
	// в неявном теге [4]. Само имя берётся из сертификата как есть.
	dirName := derWrap(0xA4, cert.RawIssuer)
	generalNames := derWrap(0x30, dirName)
	serial, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	issuerSerial := derWrap(0x30, append(append([]byte(nil), generalNames...), serial...))

	algDER, err := asn1.Marshal(algorithmIdentifier{Algorithm: digestOID})
	if err != nil {
		return nil, err
	}
	hashDER, err := asn1.Marshal(certHash)
	if err != nil {
		return nil, err
	}

	var certID []byte
	certID = append(certID, algDER...)
	certID = append(certID, hashDER...)
	certID = append(certID, issuerSerial...)
	certIDDER := derWrap(0x30, certID)

	certsSeq := derWrap(0x30, certIDDER)
	scDER := derWrap(0x30, certsSeq)

	return asn1.Marshal(attribute{
		Type: oidSigningCertificateV2,
		Values: asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: scDER,
		},
	})
}
