// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package magma реализует блочный шифр "Магма" по ГОСТ Р 34.12-2015
// (раздел 5), он же RFC 8891.
//
// Шифр работает с блоком 64 бита и ключом 256 бит. От ГОСТ 28147-89 он
// отличается двумя вещами: набор S-блоков зафиксирован
// (id-tc26-gost-28147-param-Z, RFC 7836, приложение C), а ключ и данные
// разбираются как big-endian, тогда как в 28147-89 использовался
// little-endian. Реализация 28147-89 "в лоб" даст другие подключи и другой
// шифртекст.
//
// Реализация табличная и потому не защищена от атак по времени доступа к
// кэшу. Модель угроз описана в README.
package magma

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
	"strconv"
)

const (
	// BlockSize — размер блока в байтах.
	BlockSize = 8
	// KeySize — размер ключа в байтах.
	KeySize = 32

	rounds = 32
)

// KeySizeError возвращается NewCipher при неверной длине ключа.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "magma: неверный размер ключа " + strconv.Itoa(int(k))
}

// sbox — набор подстановок id-tc26-gost-28147-param-Z (RFC 7836, прил. C).
//
// Преобразование t определено в ГОСТ Р 34.12-2015 как
// t(a) = Pi_7(a_7)||...||Pi_0(a_0), где a_0 — младший полубайт. Поэтому
// sbox[0] применяется к младшему полубайту, sbox[7] — к старшему.
var sbox = [8][16]byte{
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
}

// gTable объединяет подстановку t и циклический сдвиг на 11 разрядов влево:
// gTable[j][x] — вклад байта j (j = 0 — младший) в результат t(...) <<< 11.
//
// Свёртка корректна, потому что вклады разных байт не пересекаются, а сдвиг
// линеен относительно XOR.
var gTable [4][256]uint32

func init() {
	for j := 0; j < 4; j++ {
		for x := 0; x < 256; x++ {
			v := uint32(sbox[2*j][x&0x0f]) | uint32(sbox[2*j+1][x>>4])<<4
			gTable[j][x] = bits.RotateLeft32(v<<(8*uint(j)), 11)
		}
	}
}

// g — раундовая функция g[k](a) = t(a [+] k) <<< 11, где [+] — сложение по
// модулю 2^32 (ГОСТ Р 34.12-2015, формула для g[k]).
func g(a, k uint32) uint32 {
	s := a + k
	return gTable[0][byte(s)] ^
		gTable[1][byte(s>>8)] ^
		gTable[2][byte(s>>16)] ^
		gTable[3][byte(s>>24)]
}

type magmaCipher struct {
	rk [rounds]uint32
}

// NewCipher создаёт cipher.Block для шифра "Магма". Длина ключа должна быть
// ровно KeySize байт.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}
	c := new(magmaCipher)

	// ГОСТ Р 34.12-2015, 5.3: K_1 = k_255||...||k_224, то есть первые четыре
	// байта ключа, далее по порядку. Ключи K_1..K_8 повторяются трижды,
	// а раунды 25..32 используют их в обратном порядке.
	var k [8]uint32
	for i := range k {
		k[i] = binary.BigEndian.Uint32(key[4*i:])
	}
	for i := 0; i < 24; i++ {
		c.rk[i] = k[i%8]
	}
	for i := 0; i < 8; i++ {
		c.rk[24+i] = k[7-i]
	}
	return c, nil
}

func (c *magmaCipher) BlockSize() int { return BlockSize }

func (c *magmaCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("magma: короткий входной блок")
	}
	if len(dst) < BlockSize {
		panic("magma: короткий выходной блок")
	}
	a1 := binary.BigEndian.Uint32(src[0:4])
	a0 := binary.BigEndian.Uint32(src[4:8])

	// E = G*[K_32] G[K_31] ... G[K_1](a_1, a_0),
	// где G[k](a_1, a_0) = (a_0, g[k](a_0) xor a_1),
	// а G*[k] отличается тем, что не меняет половины местами.
	for i := 0; i < rounds-1; i++ {
		a1, a0 = a0, a1^g(a0, c.rk[i])
	}
	a1 ^= g(a0, c.rk[rounds-1])

	binary.BigEndian.PutUint32(dst[0:4], a1)
	binary.BigEndian.PutUint32(dst[4:8], a0)
}

func (c *magmaCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("magma: короткий входной блок")
	}
	if len(dst) < BlockSize {
		panic("magma: короткий выходной блок")
	}
	a1 := binary.BigEndian.Uint32(src[0:4])
	a0 := binary.BigEndian.Uint32(src[4:8])

	// D = G*[K_1] G[K_2] ... G[K_32](a_1, a_0).
	for i := rounds - 1; i > 0; i-- {
		a1, a0 = a0, a1^g(a0, c.rk[i])
	}
	a1 ^= g(a0, c.rk[0])

	binary.BigEndian.PutUint32(dst[0:4], a1)
	binary.BigEndian.PutUint32(dst[4:8], a0)
}
