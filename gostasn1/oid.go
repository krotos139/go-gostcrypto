// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package gostasn1 содержит объектные идентификаторы отечественных
// алгоритмов и кодирование ключей и подписей для PKIX (RFC 9215,
// заменивший RFC 4491).
//
// # Три несогласованных порядка байт
//
// Внутри одного сертификата встречаются все три:
//
//   - хэш переводится в целое как little-endian (ГОСТ Р 34.10-2012);
//   - r и s в подписи — big-endian, но половины идут в порядке s || r,
//     обратном порядку самого стандарта (RFC 9215, раздел 2);
//   - координаты ключа проверки — little-endian (RFC 9215, п. 4.3).
//
// Функции этого пакета скрывают перестановки: наружу они принимают и
// отдают значения в порядке пакета gost3410, то есть в порядке стандарта.
package gostasn1

import (
	"encoding/asn1"

	"github.com/krotos139/go-gostcrypto/gost3410"
)

// Идентификаторы алгоритмов (RFC 9215, разделы 2-4; Р 50.1.113-2016).
var (
	// OIDPublicKey256 — id-tc26-gost3410-12-256.
	OIDPublicKey256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// OIDPublicKey512 — id-tc26-gost3410-12-512.
	OIDPublicKey512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

	// OIDDigest256 — id-tc26-gost3411-12-256.
	OIDDigest256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	// OIDDigest512 — id-tc26-gost3411-12-512.
	OIDDigest512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

	// OIDSignWithDigest256 — id-tc26-signwithdigest-gost3410-12-256.
	OIDSignWithDigest256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	// OIDSignWithDigest512 — id-tc26-signwithdigest-gost3410-12-512.
	OIDSignWithDigest512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}

	// OIDHMAC256 — id-tc26-hmac-gost-3411-12-256.
	OIDHMAC256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 1}
	// OIDHMAC512 — id-tc26-hmac-gost-3411-12-512.
	OIDHMAC512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 2}

	// OIDCipherParamZ — id-tc26-gost-28147-param-Z, набор S-блоков "Магмы".
	OIDCipherParamZ = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}
)

// Идентификаторы устаревших алгоритмов (RFC 4357, ветвь 1.2.643.2.2).
// Они встречаются в ранее выпущенных сертификатах и подписях; для нового
// кода не предназначены.
var (
	// OIDPublicKey2001 — id-GostR3410-2001.
	OIDPublicKey2001 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	// OIDDigest94 — id-GostR3411-94.
	OIDDigest94 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
	// OIDSignWithDigest2001 — id-GostR3411-94-with-GostR3410-2001.
	OIDSignWithDigest2001 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 3}
	// OIDHashParamCryptoPro — id-GostR3411-94-CryptoProParamSet.
	OIDHashParamCryptoPro = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1}
	// OIDHashParamTest — id-GostR3411-94-TestParamSet.
	OIDHashParamTest = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 0}
)

// Идентификаторы наборов параметров кривых.
var (
	// Наборы ТК 26 (RFC 7836, разделы 5.1.1 и 5.2.1).
	OIDParamSet256A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	OIDParamSet256B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
	OIDParamSet256C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
	OIDParamSet256D = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}
	OIDParamSet512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	OIDParamSet512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	OIDParamSet512C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
	// OIDParamSet512Test — id-tc26-gost-3410-2012-512-paramSetTest;
	// применять вне тестовых сценариев запрещено.
	OIDParamSet512Test = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 0}

	// Наборы CryptoPro (RFC 4357, ветвь id-CryptoPro-ecc-signs = 1.2.643.2.2.35).
	// RFC 9215, приложение C, отождествляет их с наборами ТК 26.
	OIDParamSetCryptoProTest = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 0}
	OIDParamSetCryptoProA    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
	OIDParamSetCryptoProB    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
	OIDParamSetCryptoProC    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}
	// Наборы обмена (ветвь id-CryptoPro-ecc-exchanges = 1.2.643.2.2.36)
	// задают те же кривые, что CryptoPro-A и CryptoPro-C.
	OIDParamSetCryptoProXchA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	OIDParamSetCryptoProXchB = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}
)

// curveByOID перечисляет соответствие идентификаторов кривым. Порядок
// важен для OIDByCurve: первым для каждой кривой идёт предпочтительный
// современный идентификатор ТК 26.
var curveOIDs = []struct {
	oid   asn1.ObjectIdentifier
	curve func() *gost3410.Curve
}{
	{OIDParamSet256A, gost3410.TC26ParamSet256A},
	{OIDParamSet256B, gost3410.TC26ParamSet256B},
	{OIDParamSet256C, gost3410.TC26ParamSet256C},
	{OIDParamSet256D, gost3410.TC26ParamSet256D},
	{OIDParamSet512A, gost3410.TC26ParamSet512A},
	{OIDParamSet512B, gost3410.TC26ParamSet512B},
	{OIDParamSet512C, gost3410.TC26ParamSet512C},
	{OIDParamSet512Test, gost3410.TestParamSet512},

	{OIDParamSetCryptoProTest, gost3410.TestParamSet256},
	{OIDParamSetCryptoProA, gost3410.TC26ParamSet256B},
	{OIDParamSetCryptoProB, gost3410.TC26ParamSet256C},
	{OIDParamSetCryptoProC, gost3410.TC26ParamSet256D},
	{OIDParamSetCryptoProXchA, gost3410.TC26ParamSet256B},
	{OIDParamSetCryptoProXchB, gost3410.TC26ParamSet256D},
}

// CurveByOID возвращает кривую по идентификатору набора параметров.
func CurveByOID(oid asn1.ObjectIdentifier) (*gost3410.Curve, bool) {
	for _, e := range curveOIDs {
		if e.oid.Equal(oid) {
			return e.curve(), true
		}
	}
	return nil, false
}

// OIDByCurve возвращает предпочтительный идентификатор ТК 26 для кривой.
func OIDByCurve(c *gost3410.Curve) (asn1.ObjectIdentifier, bool) {
	for _, e := range curveOIDs {
		if e.curve() == c {
			return e.oid, true
		}
	}
	return nil, false
}

// needsDigestParamSet сообщает, обязано ли поле digestParamSet
// присутствовать для данного набора параметров (RFC 9215, п. 4.2).
// Оно требуется только для наборов, унаследованных от ГОСТ Р 34.10-2001.
func needsDigestParamSet(oid asn1.ObjectIdentifier) bool {
	for _, legacy := range []asn1.ObjectIdentifier{
		OIDParamSetCryptoProTest, OIDParamSetCryptoProA,
		OIDParamSetCryptoProB, OIDParamSetCryptoProC,
		OIDParamSetCryptoProXchA, OIDParamSetCryptoProXchB,
	} {
		if legacy.Equal(oid) {
			return true
		}
	}
	return false
}
