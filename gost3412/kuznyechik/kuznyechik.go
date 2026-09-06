// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package kuznyechik реализует блочный шифр "Кузнечик" по
// ГОСТ Р 34.12-2015 (раздел 4), он же RFC 7801.
//
// Шифр работает с блоком 128 бит и ключом 256 бит, десять раундов:
// девять преобразований LSX и завершающее наложение ключа.
//
// # Опечатка в RFC 7801
//
// В RFC 7801, п. 4.2, формула линейного преобразования содержит
// "32*delta(a_15)" вместо "32*delta(a_14)": коэффициент при a_14 потерян,
// а a_15 учтён дважды. Это RFC Errata 6928 со статусом Reported.
// Здесь используется формула (1) из ГОСТ Р 34.12-2015, где стоит
// 32*delta(a_14); реализация по тексту RFC не проходит контрольные
// примеры самого же RFC.
//
// Реализация использует таблицы умножения в поле и потому не защищена от
// атак по времени доступа к кэшу. Модель угроз описана в README.
package kuznyechik

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
)

const (
	// BlockSize — размер блока в байтах.
	BlockSize = 16
	// KeySize — размер ключа в байтах.
	KeySize = 32

	rounds = 10
)

// KeySizeError возвращается NewCipher при неверной длине ключа.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "kuznyechik: неверный размер ключа " + strconv.Itoa(int(k))
}

// block — вектор из V_128. Индекс 0 соответствует a_15, то есть старшему
// байту в шестнадцатеричной записи стандарта.
type block [BlockSize]byte

// pi — нелинейное биективное преобразование из ГОСТ Р 34.12-2015, п. 4.1.1.
var pi = [256]byte{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
}

// piInv выводится из pi, а не переписывается из стандарта: так исключается
// вторая точка для опечатки. Биективность pi проверяется в тестах.
var piInv [256]byte

// kappa — коэффициенты линейной функции l из ГОСТ Р 34.12-2015, формула (1),
// в порядке от a_15 к a_0.
var kappa = [BlockSize]byte{
	148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
}

// mulTable[j][x] — произведение kappa[j] на x в поле GF(2)[x]/p(x),
// p(x) = x^8 + x^7 + x^6 + x + 1.
var mulTable [BlockSize][256]byte

// gfMul умножает в поле, заданном многочленом p(x) = x^8+x^7+x^6+x+1.
// Старшие разряды приводятся по модулю 0xC3.
func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0xC3
		}
		b >>= 1
	}
	return p
}

func init() {
	for i, v := range pi {
		piInv[v] = byte(i)
	}
	for j := 0; j < BlockSize; j++ {
		for x := 0; x < 256; x++ {
			mulTable[j][x] = gfMul(kappa[j], byte(x))
		}
	}
}

// l вычисляет линейную функцию l(a_15, ..., a_0).
func l(b *block) byte {
	var x byte
	for i := 0; i < BlockSize; i++ {
		x ^= mulTable[i][b[i]]
	}
	return x
}

// r — преобразование R(a_15||...||a_0) = l(a_15,...,a_0)||a_15||...||a_1.
func r(b *block) {
	x := l(b)
	copy(b[1:], b[:BlockSize-1])
	b[0] = x
}

// rInv — обратное к R: a_14||...||a_0||l(a_14,...,a_0,a_15).
func rInv(b *block) {
	var x byte
	for i := 0; i < BlockSize-1; i++ {
		x ^= mulTable[i][b[i+1]]
	}
	x ^= mulTable[BlockSize-1][b[0]]
	copy(b[:BlockSize-1], b[1:])
	b[BlockSize-1] = x
}

// lTransform — L(a) = R^16(a).
func lTransform(b *block) {
	for i := 0; i < BlockSize; i++ {
		r(b)
	}
}

// lTransformInv — L^-1(a) = (R^-1)^16(a).
func lTransformInv(b *block) {
	for i := 0; i < BlockSize; i++ {
		rInv(b)
	}
}

func sTransform(b *block) {
	for i, v := range b {
		b[i] = pi[v]
	}
}

func sTransformInv(b *block) {
	for i, v := range b {
		b[i] = piInv[v]
	}
}

func xorBlock(dst, src *block) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

type kuznyechikCipher struct {
	// Раундовые ключи в машинном представлении: слово 0 — старшие 64
	// разряда блока.
	ek [rounds][2]uint64

	// Расшифрование идёт по перестроенной схеме (см. Decrypt): ключи
	// середины заранее пропущены через L^-1.
	dkFirst [2]uint64    // K_10
	dkMid   [8][2]uint64 // L^-1(K_9), L^-1(K_8), ..., L^-1(K_2)
	dkLast  [2]uint64    // K_1
}

// NewCipher создаёт cipher.Block для шифра "Кузнечик". Длина ключа должна
// быть ровно KeySize байт.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}
	c := new(kuznyechikCipher)
	c.expandKey(key)
	return c, nil
}

// expandKey реализует алгоритм развёртывания ключа (ГОСТ Р 34.12-2015, 4.3):
// итерационные константы C_i = L(Vec_128(i)), i = 1..32, и четыре группы по
// восемь раундов Фейстеля F[k](a_1, a_0) = (LSX[k](a_1) xor a_0, a_1).
func (c *kuznyechikCipher) expandKey(key []byte) {
	var consts [32]block
	for i := 1; i <= 32; i++ {
		var v block
		v[BlockSize-1] = byte(i)
		lTransform(&v)
		consts[i-1] = v
	}

	var rk [rounds]block
	copy(rk[0][:], key[:BlockSize])
	copy(rk[1][:], key[BlockSize:])

	for i := 0; i < 4; i++ {
		x, y := rk[2*i], rk[2*i+1]
		for j := 0; j < 8; j++ {
			t := x
			xorBlock(&t, &consts[8*i+j])
			sTransform(&t)
			lTransform(&t)
			xorBlock(&t, &y)
			y, x = x, t
		}
		rk[2*i+2], rk[2*i+3] = x, y
	}

	for i := range rk {
		c.ek[i] = pack(&rk[i])
	}
	c.dkFirst = c.ek[rounds-1] // K_10
	c.dkLast = c.ek[0]         // K_1
	for j := 0; j < 8; j++ {
		t := rk[8-j] // K_9, K_8, ..., K_2
		lTransformInv(&t)
		c.dkMid[j] = pack(&t)
	}
}

func (c *kuznyechikCipher) BlockSize() int { return BlockSize }

// applyPi применяет подстановку побайтно к паре слов.
func applyPi(x0, x1 uint64, subst *[256]byte) (uint64, uint64) {
	var b [BlockSize]byte
	binary.BigEndian.PutUint64(b[0:8], x0)
	binary.BigEndian.PutUint64(b[8:16], x1)
	for i := range b {
		b[i] = subst[b[i]]
	}
	return binary.BigEndian.Uint64(b[0:8]), binary.BigEndian.Uint64(b[8:16])
}

func (c *kuznyechikCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("kuznyechik: короткий входной блок")
	}
	if len(dst) < BlockSize {
		panic("kuznyechik: короткий выходной блок")
	}
	x0 := binary.BigEndian.Uint64(src[0:8])
	x1 := binary.BigEndian.Uint64(src[8:16])

	// E = X[K_10] LSX[K_9] ... LSX[K_1](a).
	for i := 0; i < rounds-1; i++ {
		x0 ^= c.ek[i][0]
		x1 ^= c.ek[i][1]
		x0, x1 = lsx(x0, x1, &encTable)
	}
	x0 ^= c.ek[rounds-1][0]
	x1 ^= c.ek[rounds-1][1]

	binary.BigEndian.PutUint64(dst[0:8], x0)
	binary.BigEndian.PutUint64(dst[8:16], x1)
}

// Decrypt вычисляет D = X[K_1] S^-1 L^-1 X[K_2] ... S^-1 L^-1 X[K_10](b).
//
// Напрямую по этой записи объединённую таблицу не построить: S^-1
// применяется после L^-1, а таблица индексируется входом. Схема
// перестраивается так. Обозначим u_j = L^-1(t_j), где t_j — состояние
// после j-го наложения ключа. Поскольку L^-1 линейно,
//
//	L^-1(S^-1(x) xor K) = L^-1(S^-1(x)) xor L^-1(K),
//
// то есть шаг превращается в g(u) xor L^-1(K), где g = L^-1 S^-1 —
// ровно то, что даёт decTable. Ключи середины заранее пропущены через
// L^-1 при развёртывании; в начале и в конце остаются по одному
// отдельному преобразованию.
func (c *kuznyechikCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("kuznyechik: короткий входной блок")
	}
	if len(dst) < BlockSize {
		panic("kuznyechik: короткий выходной блок")
	}
	x0 := binary.BigEndian.Uint64(src[0:8]) ^ c.dkFirst[0]
	x1 := binary.BigEndian.Uint64(src[8:16]) ^ c.dkFirst[1]

	// u_0 = L^-1(b xor K_10): подстановка pi компенсирует pi^-1, зашитую
	// в decTable, поэтому отдельная таблица для L^-1 не нужна.
	x0, x1 = applyPi(x0, x1, &pi)
	x0, x1 = lsx(x0, x1, &decTable)

	// u_j = g(u_{j-1}) xor L^-1(K_{10-j}): сначала преобразование, потом
	// ключ — порядок обратный тому, что в зашифровании.
	for j := 0; j < 8; j++ {
		x0, x1 = lsx(x0, x1, &decTable)
		x0 ^= c.dkMid[j][0]
		x1 ^= c.dkMid[j][1]
	}

	x0, x1 = applyPi(x0, x1, &piInv)
	x0 ^= c.dkLast[0]
	x1 ^= c.dkLast[1]

	binary.BigEndian.PutUint64(dst[0:8], x0)
	binary.BigEndian.PutUint64(dst[8:16], x1)
}
