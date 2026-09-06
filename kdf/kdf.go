// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package kdf реализует функции выработки производных ключей на основе
// хэш-функции "Стрибог":
//
//   - KDF_GOSTR3411_2012_256 и KDF_TREE_GOSTR3411_2012_256 из
//     Р 50.1.113-2016 (RFC 7836, пп. 4.4 и 4.5);
//   - PBKDF2 на HMAC_GOSTR3411_2012_512 из Р 50.1.111-2016.
package kdf

import (
	"encoding/binary"
	"errors"

	"github.com/krotos139/go-gostcrypto/mac"
)

var (
	// ErrRParam возвращается при недопустимом размере счётчика R.
	ErrRParam = errors.New("kdf: R должно быть в диапазоне от 1 до 4")
	// ErrLength возвращается при недопустимой запрошенной длине.
	ErrLength = errors.New("kdf: недопустимая длина вырабатываемого материала")
)

// lenBytes возвращает представление числа в сетевом порядке байт без
// ведущих нулей — величина [L]_b из Р 50.1.113-2016.
func lenBytes(v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

// counterBytes возвращает [i]_b — представление счётчика в r байтах.
func counterBytes(i uint64, r int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], i)
	return buf[8-r:]
}

// DeriveTree реализует KDF_TREE_GOSTR3411_2012_256:
//
//	K(i) = HMAC_256(K_in, [i]_b || label || 0x00 || seed || [L]_b)
//
// и возвращает конкатенацию K(1) || K(2) || ... длиной lBits бит.
// Параметр r задаёт размер счётчика в байтах (от 1 до 4) и ограничивает
// объём вырабатываемого материала величиной 256*(2^(8*r)-1) бит.
//
// Длина lBits должна быть кратна восьми: побитовое усечение в Go
// неудобно и на практике не используется.
func DeriveTree(kIn, label, seed []byte, r, lBits int) ([]byte, error) {
	if r < 1 || r > 4 {
		return nil, ErrRParam
	}
	if lBits <= 0 || lBits%8 != 0 {
		return nil, ErrLength
	}
	maxBits := uint64(mac.Size256) * 8 * ((1 << (8 * uint(r))) - 1)
	if uint64(lBits) > maxBits {
		return nil, ErrLength
	}

	lb := lenBytes(uint64(lBits))
	out := make([]byte, 0, (lBits+7)/8)
	for i := uint64(1); len(out)*8 < lBits; i++ {
		h := mac.New256(kIn)
		h.Write(counterBytes(i, r))
		h.Write(label)
		h.Write([]byte{0x00})
		h.Write(seed)
		h.Write(lb)
		out = h.Sum(out)
	}
	return out[:lBits/8], nil
}

// Derive реализует KDF_GOSTR3411_2012_256 — частный случай DeriveTree при
// r = 1 и L = 256:
//
//	KDF(K_in, label, seed) =
//	    HMAC_256(K_in, 0x01 || label || 0x00 || seed || 0x01 || 0x00)
func Derive(kIn, label, seed []byte) []byte {
	out, err := DeriveTree(kIn, label, seed, 1, 256)
	if err != nil {
		// Параметры фиксированы и заведомо допустимы.
		panic("kdf: " + err.Error())
	}
	return out
}
