// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
	"github.com/krotos139/go-gostcrypto/legacy/gost341194"
)

var (
	// ErrUnsupportedAlgorithm возвращается для неизвестного идентификатора.
	ErrUnsupportedAlgorithm = errors.New("gostasn1: неизвестный алгоритм или набор параметров")
	// ErrMalformed возвращается при некорректной структуре DER.
	ErrMalformed = errors.New("gostasn1: некорректная структура")
	// ErrSignature возвращается, если подпись не прошла проверку.
	ErrSignature = errors.New("gostasn1: подпись не прошла проверку")
)

// publicKeyParameters — GostR3410-2012-PublicKeyParameters
// (RFC 9215, п. 4.2).
type publicKeyParameters struct {
	PublicKeyParamSet asn1.ObjectIdentifier
	DigestParamSet    asn1.ObjectIdentifier `asn1:"optional"`
}

// subjectPublicKeyInfo — стандартная структура из RFC 5280.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// reverse разворачивает срез на месте.
func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// ParsePublicKey разбирает SubjectPublicKeyInfo в DER-кодировке.
//
// Координаты записаны от младшего байта к старшему: x в первой половине,
// y во второй (RFC 9215, п. 4.3).
func ParsePublicKey(der []byte) (*gost3410.PublicKey, error) {
	var spki subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(der, &spki); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	// Ключи ГОСТ Р 34.10-2001 кодируются так же, как 256-битные ключи
	// ГОСТ Р 34.10-2012 (RFC 4491), поэтому разбираются тем же кодом.
	if !spki.Algorithm.Algorithm.Equal(OIDPublicKey256) &&
		!spki.Algorithm.Algorithm.Equal(OIDPublicKey512) &&
		!spki.Algorithm.Algorithm.Equal(OIDPublicKey2001) {
		return nil, ErrUnsupportedAlgorithm
	}

	var params publicKeyParameters
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, ErrMalformed
	}
	curve, ok := CurveByOID(params.PublicKeyParamSet)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	// Идентификатор алгоритма обязан соответствовать разрядности набора
	// параметров: ...gost3410-12-512 только с 512-битной кривой, прочие
	// только с 256-битной. Без этой сверки одна и та же точка получает
	// два разных допустимых представления, а такая неоднозначность в
	// разборе ключей недопустима.
	want := 32
	if spki.Algorithm.Algorithm.Equal(OIDPublicKey512) {
		want = 64
	}
	if curve.Size() != want {
		return nil, ErrMalformed
	}

	// Содержимое BIT STRING — DER-кодировка OCTET STRING с координатами.
	var raw []byte
	if rest, err := asn1.Unmarshal(spki.PublicKey.RightAlign(), &raw); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	return unmarshalPoint(curve, raw)
}

// unmarshalPoint восстанавливает точку из 2*Size() байт: x и y записаны
// от младшего байта к старшему.
func unmarshalPoint(c *gost3410.Curve, raw []byte) (*gost3410.PublicKey, error) {
	size := c.Size()
	if len(raw) != 2*size {
		return nil, ErrMalformed
	}
	xb := append([]byte(nil), raw[:size]...)
	yb := append([]byte(nil), raw[size:]...)
	reverse(xb)
	reverse(yb)

	pub, err := gost3410.NewPublicKey(c, new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb))
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// MarshalPublicKey кодирует ключ проверки в SubjectPublicKeyInfo.
func MarshalPublicKey(pub *gost3410.PublicKey) ([]byte, error) {
	paramOID, ok := OIDByCurve(pub.Curve)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	size := pub.Curve.Size()

	algOID := OIDPublicKey256
	if size > 32 {
		algOID = OIDPublicKey512
	}

	params := publicKeyParameters{PublicKeyParamSet: paramOID}
	if needsDigestParamSet(paramOID) {
		params.DigestParamSet = OIDDigest256
	}
	paramBytes, err := asn1.Marshal(params)
	if err != nil {
		return nil, err
	}

	raw := make([]byte, 2*size)
	pub.X.FillBytes(raw[:size])
	pub.Y.FillBytes(raw[size:])
	reverse(raw[:size])
	reverse(raw[size:])

	inner, err := asn1.Marshal(raw)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  algOID,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		PublicKey: asn1.BitString{Bytes: inner, BitLength: 8 * len(inner)},
	})
}

// SignatureToPKIX переставляет половины подписи из порядка стандарта
// (r || s) в порядок PKIX и CMS (s || r). Преобразование обратно самому
// себе, но две функции названы по направлению, чтобы вызов читался.
func SignatureToPKIX(sig []byte) ([]byte, error) { return swapHalves(sig) }

// SignatureFromPKIX переставляет половины подписи из порядка PKIX
// (s || r) в порядок стандарта (r || s).
func SignatureFromPKIX(sig []byte) ([]byte, error) { return swapHalves(sig) }

func swapHalves(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, ErrMalformed
	}
	half := len(sig) / 2
	out := make([]byte, len(sig))
	copy(out[:half], sig[half:])
	copy(out[half:], sig[:half])
	return out, nil
}

// certificate повторяет внешнюю структуру X.509: crypto/x509 не отдаёт
// идентификатор алгоритма подписи для неизвестных ему алгоритмов.
type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// PublicKeyFromCertificate извлекает ключ проверки из сертификата.
//
// crypto/x509 не умеет разбирать отечественные ключи и оставляет поле
// PublicKey пустым, поэтому используется RawSubjectPublicKeyInfo.
func PublicKeyFromCertificate(cert *x509.Certificate) (*gost3410.PublicKey, error) {
	return ParsePublicKey(cert.RawSubjectPublicKeyInfo)
}

// CheckCertificateSignature проверяет подпись сертификата ключом pub.
//
// Длина хэш-кода выбирается по идентификатору алгоритма подписи:
// id-tc26-signwithdigest-gost3410-12-256 требует "Стрибога" с 256-битным
// хэш-кодом, ...-512 — с 512-битным (RFC 9215, раздел 2).
func CheckCertificateSignature(cert *x509.Certificate, pub *gost3410.PublicKey) error {
	var c certificate
	if _, err := asn1.Unmarshal(cert.Raw, &c); err != nil {
		return ErrMalformed
	}

	var digest []byte
	switch {
	case c.SignatureAlgorithm.Algorithm.Equal(OIDSignWithDigest256):
		d := streebog.Sum256(c.TBSCertificate.FullBytes)
		digest = d[:]
	case c.SignatureAlgorithm.Algorithm.Equal(OIDSignWithDigest512):
		d := streebog.Sum512(c.TBSCertificate.FullBytes)
		digest = d[:]
	case c.SignatureAlgorithm.Algorithm.Equal(OIDSignWithDigest2001),
		c.SignatureAlgorithm.Algorithm.Equal(OIDPublicKey2001):
		// Устаревшая пара: хэш ГОСТ Р 34.11-94 с набором CryptoPro.
		d := gost341194.Sum256(c.TBSCertificate.FullBytes)
		digest = d[:]
	default:
		return ErrUnsupportedAlgorithm
	}

	sig, err := SignatureFromPKIX(c.SignatureValue.RightAlign())
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

// SignatureAlgorithmOID возвращает идентификатор алгоритма подписи,
// соответствующий длине ключа кривой.
func SignatureAlgorithmOID(c *gost3410.Curve) asn1.ObjectIdentifier {
	if c.Size() > 32 {
		return OIDSignWithDigest512
	}
	return OIDSignWithDigest256
}

// DigestForCurve возвращает хэш-код сообщения той длины, которая
// соответствует ключу данной кривой.
func DigestForCurve(c *gost3410.Curve, data []byte) []byte {
	if c.Size() > 32 {
		d := streebog.Sum512(data)
		return d[:]
	}
	d := streebog.Sum256(data)
	return d[:]
}
