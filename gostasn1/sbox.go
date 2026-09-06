// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"encoding/asn1"
	"errors"

	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

// Идентификаторы наборов подстановок ГОСТ 28147-89 (RFC 4357, п. 11.2).
//
// Наборы задают не только подстановки, но и режим работы шифра с
// ключевым размешиванием; здесь нужны только подстановки — их выбирает
// зашифрованное сообщение CMS в поле encryptionParamSet.
var (
	// OIDCipherTestParamSet — id-Gost28147-89-TestParamSet.
	OIDCipherTestParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 0}
	// OIDCipherCryptoProA — id-Gost28147-89-CryptoPro-A-ParamSet.
	OIDCipherCryptoProA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}
	// OIDCipherCryptoProB — id-Gost28147-89-CryptoPro-B-ParamSet.
	OIDCipherCryptoProB = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 2}
	// OIDCipherCryptoProC — id-Gost28147-89-CryptoPro-C-ParamSet.
	OIDCipherCryptoProC = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 3}
	// OIDCipherCryptoProD — id-Gost28147-89-CryptoPro-D-ParamSet.
	OIDCipherCryptoProD = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 4}
)

// ErrUnknownParamSet возвращается для неизвестного набора подстановок.
var ErrUnknownParamSet = errors.New("gostasn1: неизвестный набор подстановок")

// SBoxByOID возвращает набор подстановок по его идентификатору.
func SBoxByOID(oid asn1.ObjectIdentifier) (*gost28147.SBox, error) {
	switch {
	case oid.Equal(OIDCipherTestParamSet):
		return gost28147.ParamTest(), nil
	case oid.Equal(OIDCipherCryptoProA):
		return gost28147.ParamCryptoProA(), nil
	case oid.Equal(OIDCipherCryptoProB):
		return gost28147.ParamCryptoProB(), nil
	case oid.Equal(OIDCipherCryptoProC):
		return gost28147.ParamCryptoProC(), nil
	case oid.Equal(OIDCipherCryptoProD):
		return gost28147.ParamCryptoProD(), nil
	case oid.Equal(OIDCipherParamZ):
		return gost28147.ParamZ(), nil
	}
	return nil, ErrUnknownParamSet
}
