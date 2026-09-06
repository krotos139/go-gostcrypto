// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package mac реализует HMAC на основе хэш-функции "Стрибог":
// HMAC_GOSTR3411_2012_256 и HMAC_GOSTR3411_2012_512 из Р 50.1.113-2016
// (RFC 7836, п. 4.1).
//
// Никаких отличий от обычного HMAC (RFC 2104) здесь нет: ipad и opad
// формируются как обычно, а размер блока итерационной процедуры равен
// 64 байтам для обеих длин хэш-кода — это важно, потому что у
// 256-битного варианта выход вдвое короче блока.
package mac

import (
	"crypto/hmac"
	"hash"

	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
)

// Size256 и Size512 — длины имитовставки в байтах.
const (
	Size256 = streebog.Size256
	Size512 = streebog.Size
	// BlockSize — размер блока итерационной процедуры (B в терминах RFC 2104).
	BlockSize = streebog.BlockSize
)

// New256 возвращает HMAC_GOSTR3411_2012_256 с заданным ключом.
func New256(key []byte) hash.Hash { return hmac.New(streebog.New256, key) }

// New512 возвращает HMAC_GOSTR3411_2012_512 с заданным ключом.
func New512(key []byte) hash.Hash { return hmac.New(streebog.New512, key) }

// Sum256 вычисляет HMAC_GOSTR3411_2012_256 за один вызов.
func Sum256(key, data []byte) []byte {
	h := New256(key)
	h.Write(data)
	return h.Sum(nil)
}

// Sum512 вычисляет HMAC_GOSTR3411_2012_512 за один вызов.
func Sum512(key, data []byte) []byte {
	h := New512(key)
	h.Write(data)
	return h.Sum(nil)
}

// Equal сравнивает две имитовставки за время, не зависящее от данных.
func Equal(a, b []byte) bool { return hmac.Equal(a, b) }
