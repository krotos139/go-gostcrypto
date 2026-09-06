// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
	"github.com/krotos139/go-gostcrypto/legacy/gost341194"
)

// Запросы на сертификат и списки отзыва (RFC 9215, приложение D).
//
// crypto/x509 разбирает обе структуры, но проверить подпись под ними не
// может: отечественных алгоритмов он не знает и оставляет поле открытого
// ключа пустым. Здесь недостающее восполняется — так же, как это делает
// CheckCertificateSignature для сертификатов.

type tbsRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	TBS                tbsRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type certificateList struct {
	TBSCertList        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// digestForSignatureOID возвращает хэш-код нужной длины по
// идентификатору алгоритма подписи.
func digestForSignatureOID(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	switch {
	case oid.Equal(OIDSignWithDigest256):
		d := streebog.Sum256(data)
		return d[:], nil
	case oid.Equal(OIDSignWithDigest512):
		d := streebog.Sum512(data)
		return d[:], nil
	case oid.Equal(OIDSignWithDigest2001), oid.Equal(OIDPublicKey2001):
		d := gost341194.Sum256(data)
		return d[:], nil
	}
	return nil, ErrUnsupportedAlgorithm
}

// PublicKeyFromCertificateRequest извлекает ключ проверки из запроса.
func PublicKeyFromCertificateRequest(req *x509.CertificateRequest) (*gost3410.PublicKey, error) {
	return ParsePublicKey(req.RawSubjectPublicKeyInfo)
}

// CheckCertificateRequestSignature проверяет подпись под запросом на
// сертификат.
//
// Запрос подписывается тем же ключом, на который запрашивается
// сертификат: это доказывает удостоверяющему центру, что заявитель
// владеет секретным ключом. Поэтому ключ проверки берётся из самого
// запроса.
func CheckCertificateRequestSignature(req *x509.CertificateRequest) error {
	var r certificateRequest
	if _, err := asn1.Unmarshal(req.Raw, &r); err != nil {
		return ErrMalformed
	}
	pub, err := PublicKeyFromCertificateRequest(req)
	if err != nil {
		return err
	}
	digest, err := digestForSignatureOID(r.SignatureAlgorithm.Algorithm, r.TBS.Raw)
	if err != nil {
		return err
	}
	sig, err := SignatureFromPKIX(r.SignatureValue.RightAlign())
	if err != nil {
		return err
	}
	if len(sig) != 2*pub.Curve.Size() {
		return ErrMalformed
	}
	if !gost3410.Verify(pub, digest, sig) {
		return ErrSignature
	}
	return nil
}

// CheckCRLSignature проверяет подпись под списком отзыва ключом pub.
//
// Ключ берётся из сертификата удостоверяющего центра, выпустившего
// список; сам факт доверия к этому центру остаётся за вызывающим кодом.
func CheckCRLSignature(der []byte, pub *gost3410.PublicKey) error {
	var l certificateList
	if rest, err := asn1.Unmarshal(der, &l); err != nil || len(rest) != 0 {
		return ErrMalformed
	}
	digest, err := digestForSignatureOID(l.SignatureAlgorithm.Algorithm, l.TBSCertList.FullBytes)
	if err != nil {
		return err
	}
	sig, err := SignatureFromPKIX(l.SignatureValue.RightAlign())
	if err != nil {
		return err
	}
	if len(sig) != 2*pub.Curve.Size() {
		return ErrMalformed
	}
	if !gost3410.Verify(pub, digest, sig) {
		return ErrSignature
	}
	return nil
}

// CreateCertificateRequest выпускает запрос на сертификат, подписанный
// ключом priv.
//
// Разбирается он обычным x509.ParseCertificateRequest, а проверяется
// через CheckCertificateRequestSignature.
func CreateCertificateRequest(rand io.Reader, subject pkix.Name, priv *gost3410.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, ErrMalformed
	}
	spki, err := MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	versionDER, err := asn1.Marshal(0)
	if err != nil {
		return nil, err
	}

	// attributes [0] IMPLICIT SET OF Attribute: поле обязательное, но
	// пустое множество допустимо.
	var tbs []byte
	tbs = append(tbs, versionDER...)
	tbs = append(tbs, subjectDER...)
	tbs = append(tbs, spki...)
	tbs = append(tbs, 0xA0, 0x00)
	tbsDER := derWrapASN1(0x30, tbs)

	algDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm: SignatureAlgorithmOID(priv.Curve),
	})
	if err != nil {
		return nil, err
	}

	sig, err := gost3410.Sign(rand, priv, DigestForCurve(priv.Curve, tbsDER))
	if err != nil {
		return nil, err
	}
	sigPKIX, err := SignatureToPKIX(sig)
	if err != nil {
		return nil, err
	}
	sigDER, err := asn1.Marshal(asn1.BitString{Bytes: sigPKIX, BitLength: len(sigPKIX) * 8})
	if err != nil {
		return nil, err
	}

	body := append(append(append([]byte(nil), tbsDER...), algDER...), sigDER...)
	return derWrapASN1(0x30, body), nil
}

// derWrapASN1 заворачивает содержимое в элемент DER с заданным тегом.
func derWrapASN1(tag byte, body []byte) []byte {
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}
