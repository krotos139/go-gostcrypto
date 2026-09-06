// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package streebog реализует хэш-функцию "Стрибог" по ГОСТ Р 34.11-2012,
// она же RFC 6986, с длиной хэш-кода 256 и 512 бит.
//
// # Порядок байт
//
// Это главный источник несовместимости между реализациями. И стандарт, и
// RFC записывают все векторы старшим разрядом влево, а разряды нумеруют
// справа налево — из-за чего шестнадцатеричная запись контрольного примера
// оказывается развёрнутой относительно потока данных. Контрольное
// сообщение M1 из RFC 6986 — это ASCII-строка "012345...012", напечатанная
// задом наперёд, а эталон 486f64c1... — байтовый разворот "естественного"
// хэша ...c1646f48.
//
// Здесь состояние хранится как восемь слов uint64 в порядке от младшего к
// старшему, поэтому байты потока ложатся в него напрямую (little-endian), а
// хэш выдаётся в том же порядке индексов. Никаких разворотов на входе и
// выходе не требуется: развёрнуты именно записи в стандарте, а не данные.
//
// Реализация табличная и потому не защищена от атак по времени доступа к
// кэшу. Модель угроз описана в README.
package streebog

import (
	"encoding"
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

const (
	// BlockSize — размер блока в байтах.
	BlockSize = 64
	// Size — длина хэш-кода в байтах для 512-битного варианта.
	Size = 64
	// Size256 — длина хэш-кода в байтах для 256-битного варианта.
	Size256 = 32
)

// state — вектор из V_512. Слово 0 хранит младшие 64 разряда, то есть
// первые восемь байт потока.
type state [8]uint64

type digest struct {
	h    state
	n    state // счётчик длины N
	sig  state // контрольная сумма EPSILON
	buf  [BlockSize]byte
	nx   int
	size int
}

var (
	_ hash.Hash                  = (*digest)(nil)
	_ encoding.BinaryMarshaler   = (*digest)(nil)
	_ encoding.BinaryUnmarshaler = (*digest)(nil)
	_ encoding.BinaryAppender    = (*digest)(nil)
)

// New512 возвращает hash.Hash, вычисляющий 512-битный хэш-код.
func New512() hash.Hash {
	d := &digest{size: Size}
	d.Reset()
	return d
}

// New256 возвращает hash.Hash, вычисляющий 256-битный хэш-код.
//
// Это не усечение 512-битного результата: у 256-битного варианта другое
// начальное значение, поэтому хэш-коды никак не связаны.
func New256() hash.Hash {
	d := &digest{size: Size256}
	d.Reset()
	return d
}

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	// IV: 0^512 для 512 бит и повторение байта 0x01 для 256 бит
	// (ГОСТ Р 34.11-2012, 6.1).
	var iv uint64
	if d.size == Size256 {
		iv = 0x0101010101010101
	}
	for i := range d.h {
		d.h[i] = iv
		d.n[i] = 0
		d.sig[i] = 0
	}
	for i := range d.buf {
		d.buf[i] = 0
	}
	d.nx = 0
}

// lps вычисляет LPS(src): подстановка S, перестановка байт P и линейное
// преобразование L. Результат собирается во временную переменную, поэтому
// dst и src могут совпадать.
func lps(dst, src *state) {
	var r state
	for j := 0; j < 8; j++ {
		sh := 8 * uint(j)
		r[j] = lpsTable[0][byte(src[0]>>sh)] ^
			lpsTable[1][byte(src[1]>>sh)] ^
			lpsTable[2][byte(src[2]>>sh)] ^
			lpsTable[3][byte(src[3]>>sh)] ^
			lpsTable[4][byte(src[4]>>sh)] ^
			lpsTable[5][byte(src[5]>>sh)] ^
			lpsTable[6][byte(src[6]>>sh)] ^
			lpsTable[7][byte(src[7]>>sh)]
	}
	*dst = r
}

// g вычисляет h := g_n(h, m) = E(LPS(h xor n), m) xor h xor m
// (ГОСТ Р 34.11-2012, раздел 8). Аргументы не изменяются.
func (d *digest) g(m, n *state) {
	var k, t state

	for i := range k {
		k[i] = d.h[i] ^ n[i]
	}
	lps(&k, &k) // K[1]

	t = *m
	// E(K, m) = X[K13] LPSX[K12] ... LPSX[K1](m),
	// K[i] = LPS(K[i-1] xor C[i-1]).
	for i := 0; i < 12; i++ {
		for j := range t {
			t[j] ^= k[j]
		}
		lps(&t, &t)
		for j := range k {
			k[j] ^= c[i][j]
		}
		lps(&k, &k)
	}
	for j := range t {
		t[j] ^= k[j] // X[K13]
	}

	for i := range d.h {
		d.h[i] ^= t[i] ^ m[i]
	}
}

// add складывает два 512-разрядных числа по модулю 2^512.
func add(dst *state, src *state) {
	var carry uint64
	for i := 0; i < 8; i++ {
		dst[i], carry = bits.Add64(dst[i], src[i], carry)
	}
}

// addUint прибавляет небольшое число к 512-разрядному счётчику.
func addUint(dst *state, v uint64) {
	var carry uint64
	dst[0], carry = bits.Add64(dst[0], v, 0)
	for i := 1; i < 8 && carry != 0; i++ {
		dst[i], carry = bits.Add64(dst[i], 0, carry)
	}
}

func load(m *state, p []byte) {
	for i := 0; i < 8; i++ {
		m[i] = binary.LittleEndian.Uint64(p[8*i:])
	}
}

// block обрабатывает полный блок: шаги 2.3-2.5 стандарта.
func (d *digest) block(p []byte) {
	var m state
	load(&m, p)
	d.g(&m, &d.n)
	addUint(&d.n, BlockSize*8)
	add(&d.sig, &m)
}

func (d *digest) Write(p []byte) (int, error) {
	total := len(p)

	if d.nx > 0 {
		k := copy(d.buf[d.nx:], p)
		d.nx += k
		p = p[k:]
		if d.nx == BlockSize {
			d.block(d.buf[:])
			d.nx = 0
		}
	}
	for len(p) >= BlockSize {
		d.block(p[:BlockSize])
		p = p[BlockSize:]
	}
	if len(p) > 0 {
		d.nx = copy(d.buf[:], p)
	}
	return total, nil
}

// Sum дописывает хэш-код к in, не изменяя состояние.
func (d *digest) Sum(in []byte) []byte {
	// digest состоит только из массивов и чисел, поэтому присваивание
	// копирует состояние целиком.
	tmp := *d
	return append(in, tmp.checkSum()...)
}

// checkSum выполняет шаг 3 стандарта: дополнение, завершающий блок и две
// свёртки с нулевым счётчиком.
func (d *digest) checkSum() []byte {
	// m := 0^(511-|M|) || 1 || M — в потоковом порядке это дописанный
	// байт 0x01 и нули до конца блока.
	var pad [BlockSize]byte
	copy(pad[:], d.buf[:d.nx])
	pad[d.nx] = 0x01

	var m state
	load(&m, pad[:])
	d.g(&m, &d.n)
	addUint(&d.n, uint64(d.nx)*8)
	add(&d.sig, &m)

	var zero state
	d.g(&d.n, &zero)   // h := g_0(h, N)
	d.g(&d.sig, &zero) // h := g_0(h, EPSILON)

	var out [Size]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], d.h[i])
	}
	if d.size == Size256 {
		// MSB_256 — старшие 256 разрядов, то есть байты с индексами 32..63.
		return out[Size-Size256:]
	}
	return out[:]
}

// --- сериализация состояния -----------------------------------------------

const (
	magic256    = "gost3411\x02"
	magic512    = "gost3411\x04"
	marshaledSz = len(magic512) + 3*8*8 + BlockSize + 1
)

// ErrState возвращается UnmarshalBinary, если снимок состояния повреждён
// или снят с хэша другой длины.
var ErrState = errors.New("streebog: некорректный снимок состояния")

func (d *digest) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSz)
	if d.size == Size256 {
		b = append(b, magic256...)
	} else {
		b = append(b, magic512...)
	}
	for _, w := range [3]state{d.h, d.n, d.sig} {
		for _, v := range w {
			b = binary.BigEndian.AppendUint64(b, v)
		}
	}
	b = append(b, d.buf[:]...)
	b = append(b, byte(d.nx))
	return b, nil
}

func (d *digest) AppendBinary(b []byte) ([]byte, error) {
	s, err := d.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(b, s...), nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) != marshaledSz {
		return ErrState
	}
	want := magic512
	if d.size == Size256 {
		want = magic256
	}
	if string(b[:len(want)]) != want {
		return ErrState
	}
	b = b[len(want):]

	for _, w := range []*state{&d.h, &d.n, &d.sig} {
		for i := range w {
			w[i] = binary.BigEndian.Uint64(b)
			b = b[8:]
		}
	}
	copy(d.buf[:], b)
	b = b[BlockSize:]

	nx := int(b[0])
	if nx >= BlockSize {
		return ErrState
	}
	d.nx = nx
	return nil
}

// --- удобные обёртки ------------------------------------------------------

// Sum512 возвращает 512-битный хэш-код сообщения.
func Sum512(data []byte) [Size]byte {
	d := digest{size: Size}
	d.Reset()
	d.Write(data)
	var out [Size]byte
	copy(out[:], d.checkSum())
	return out
}

// Sum256 возвращает 256-битный хэш-код сообщения.
func Sum256(data []byte) [Size256]byte {
	d := digest{size: Size256}
	d.Reset()
	d.Write(data)
	var out [Size256]byte
	copy(out[:], d.checkSum())
	return out
}
