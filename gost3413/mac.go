// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import (
	"crypto/cipher"
	"errors"
	"hash"
)

// Режим выработки имитовставки (ГОСТ Р 34.13-2015, 5.6). Стандарт прямо
// указывает, что режим реализует конструкцию OMAC1, стандартизованную в
// ISO под названием CMAC:
//
//	C_0 = 0^n
//	C_i = e_K(P_i xor C_{i-1}),  i = 1, ..., q-1
//	MAC = T_s(e_K(P*_q xor C_{q-1} xor K*))
//
// где K* = K1, если последний блок полный, и K2 иначе, а P*_q — последний
// блок после дополнения по процедуре 3.

// ErrTagSize возвращается NewMAC при недопустимой длине имитовставки.
var ErrTagSize = errors.New("gost3413: недопустимая длина имитовставки")

var _ hash.Hash = (*MAC)(nil)

// MAC вычисляет имитовставку в режиме ГОСТ Р 34.13-2015, 5.6.
// Реализует hash.Hash: данные подаются через Write, результат снимается
// через Sum. Sum не изменяет состояние, поэтому его можно вызывать
// многократно и продолжать дописывать данные.
type MAC struct {
	b      cipher.Block
	bs     int
	k1, k2 []byte
	c      []byte // C_{i-1}
	buf    []byte // отложенный блок, ровно bs байт ёмкости
	nbuf   int
	size   int
	total  int // сколько байт всего записано; нужно, чтобы отличить пустое сообщение
}

// bnConst возвращает константу B_n из п. 5.6.1 стандарта.
// B_64 = 0^59 || 11011, B_128 = 0^120 || 10000111 — обе умещаются в
// младший байт.
func bnConst(blockSize int) (byte, bool) {
	switch blockSize {
	case 8:
		return 0x1B, true
	case 16:
		return 0x87, true
	default:
		// Для других n стандарт определяет B_n через примитивные
		// многочлены; таких блочных шифров в ГОСТ Р 34.12 нет.
		return 0, false
	}
}

// shiftLeft1 записывает в dst сдвиг src на один разряд влево и возвращает
// вытесненный старший бит.
func shiftLeft1(dst, src []byte) byte {
	carry := src[0] >> 7
	for i := 0; i < len(src)-1; i++ {
		dst[i] = src[i]<<1 | src[i+1]>>7
	}
	dst[len(src)-1] = src[len(src)-1] << 1
	return carry
}

// deriveSubkeys вычисляет R, K1 и K2 по п. 5.6.1 стандарта.
func deriveSubkeys(b cipher.Block) (r, k1, k2 []byte, err error) {
	bs := b.BlockSize()
	bn, ok := bnConst(bs)
	if !ok {
		return nil, nil, nil, ErrBlockSize
	}

	r = make([]byte, bs)
	b.Encrypt(r, make([]byte, bs))

	k1 = make([]byte, bs)
	if shiftLeft1(k1, r) == 1 {
		k1[bs-1] ^= bn
	}
	k2 = make([]byte, bs)
	if shiftLeft1(k2, k1) == 1 {
		k2[bs-1] ^= bn
	}
	return r, k1, k2, nil
}

// NewMAC создаёт вычислитель имитовставки длины tagSize байт
// (0 < tagSize <= n).
//
// Вспомогательные ключи K1 и K2 наряду с ключом шифра являются секретными:
// компрометация любого из них позволяет подделывать имитовставки.
func NewMAC(b cipher.Block, tagSize int) (*MAC, error) {
	bs := b.BlockSize()
	if tagSize <= 0 || tagSize > bs {
		return nil, ErrTagSize
	}
	_, k1, k2, err := deriveSubkeys(b)
	if err != nil {
		return nil, err
	}
	return &MAC{
		b:    b,
		bs:   bs,
		k1:   k1,
		k2:   k2,
		c:    make([]byte, bs),
		buf:  make([]byte, bs),
		size: tagSize,
	}, nil
}

// Size возвращает длину имитовставки в байтах.
func (m *MAC) Size() int { return m.size }

// BlockSize возвращает размер блока базового шифра.
func (m *MAC) BlockSize() int { return m.bs }

// Reset возвращает вычислитель в исходное состояние, сохраняя ключи.
func (m *MAC) Reset() {
	for i := range m.c {
		m.c[i] = 0
	}
	for i := range m.buf {
		m.buf[i] = 0
	}
	m.nbuf = 0
	m.total = 0
}

func (m *MAC) Write(p []byte) (int, error) {
	n := len(p)
	m.total += n
	for len(p) > 0 {
		if m.nbuf == m.bs {
			// Блок заполнен, но данные ещё есть — значит он не последний
			// и обрабатывается по общей формуле.
			xorBytes(m.c, m.c, m.buf, m.bs)
			m.b.Encrypt(m.c, m.c)
			m.nbuf = 0
		}
		k := copy(m.buf[m.nbuf:], p)
		m.nbuf += k
		p = p[k:]
	}
	return n, nil
}

// Sum дописывает имитовставку к in. Состояние вычислителя не меняется.
func (m *MAC) Sum(in []byte) []byte {
	c := make([]byte, m.bs)
	copy(c, m.c)

	last := make([]byte, m.bs)
	copy(last, m.buf[:m.nbuf])

	// Процедура дополнения 3: полный последний блок не дополняется и
	// складывается с K1, неполный дополняется и складывается с K2.
	// Пустое сообщение считается неполным блоком.
	k := m.k1
	if m.total == 0 || m.nbuf != m.bs {
		last[m.nbuf] = 0x80
		k = m.k2
	}

	xorBytes(c, c, last, m.bs)
	xorBytes(c, c, k, m.bs)
	m.b.Encrypt(c, c)

	return append(in, c[:m.size]...)
}
