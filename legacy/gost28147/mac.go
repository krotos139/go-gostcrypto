// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost28147

import (
	"encoding/binary"
	"errors"
	"hash"
)

// Режим выработки имитовставки ГОСТ 28147-89 (RFC 5830, раздел 8).
//
// От режима шифрования он отличается тем, что использует только первые
// шестнадцать раундов: содержимое регистров складывается по модулю 2 с
// очередным блоком открытого текста и прогоняется через шестнадцать
// раундов, результат складывается со следующим блоком и так далее.
// Имитовставкой служат старшие разряды регистра N1.
//
// Стандарт определяет режим для сообщений не короче двух блоков и с
// нулевым начальным значением. Ненулевое начальное значение используется
// в схеме экспорта ключа из RFC 7836, п. 4.6, поэтому здесь оно задаётся
// параметром.

// ErrMACSize возвращается NewMAC при недопустимой длине имитовставки.
var ErrMACSize = errors.New("gost28147: недопустимая длина имитовставки")

// ErrIVSize возвращается NewMAC при недопустимой длине начального значения.
var ErrIVSize = errors.New("gost28147: начальное значение должно занимать блок")

type macState struct {
	c      *Cipher
	n1, n2 uint32
	iv1    uint32
	iv2    uint32
	buf    [BlockSize]byte
	nx     int
	size   int
}

var _ hash.Hash = (*macState)(nil)

// NewMAC создаёт вычислитель имитовставки длины size байт (от 1 до
// BlockSize/2, то есть до четырёх). Длина iv должна быть либо нулевой,
// либо равной размеру блока.
func NewMAC(key []byte, sbox *SBox, iv []byte, size int) (hash.Hash, error) {
	if size <= 0 || size > BlockSize/2 {
		return nil, ErrMACSize
	}
	if len(iv) != 0 && len(iv) != BlockSize {
		return nil, ErrIVSize
	}
	c, err := NewCipher(key, sbox)
	if err != nil {
		return nil, err
	}
	m := &macState{c: c.(*Cipher), size: size}
	if len(iv) == BlockSize {
		m.iv1 = binary.LittleEndian.Uint32(iv[0:4])
		m.iv2 = binary.LittleEndian.Uint32(iv[4:8])
	}
	m.Reset()
	return m, nil
}

func (m *macState) Size() int      { return m.size }
func (m *macState) BlockSize() int { return BlockSize }

func (m *macState) Reset() {
	m.n1, m.n2 = m.iv1, m.iv2
	m.buf = [BlockSize]byte{}
	m.nx = 0
}

// round16 прогоняет содержимое регистров через первые шестнадцать
// раундов: подключи X0..X7 используются дважды.
func (m *macState) round16() {
	n1, n2 := m.n1, m.n2
	for i := 0; i < 16; i++ {
		n1, n2 = n2^m.c.f(n1, m.c.rk[i]), n1
	}
	m.n1, m.n2 = n1, n2
}

func (m *macState) block(p []byte) {
	m.n1 ^= binary.LittleEndian.Uint32(p[0:4])
	m.n2 ^= binary.LittleEndian.Uint32(p[4:8])
	m.round16()
}

func (m *macState) Write(p []byte) (int, error) {
	total := len(p)

	if m.nx > 0 {
		k := copy(m.buf[m.nx:], p)
		m.nx += k
		p = p[k:]
		if m.nx == BlockSize {
			m.block(m.buf[:])
			m.nx = 0
		}
	}
	for len(p) >= BlockSize {
		m.block(p[:BlockSize])
		p = p[BlockSize:]
	}
	if len(p) > 0 {
		m.nx = copy(m.buf[:], p)
	}
	return total, nil
}

// Sum дописывает имитовставку к in, не изменяя состояние.
//
// Неполный последний блок дополняется нулями. Для пустого сообщения
// возвращается усечённое начальное значение: стандарт такой случай не
// определяет, режим предназначен для сообщений не короче двух блоков.
func (m *macState) Sum(in []byte) []byte {
	tmp := *m
	if tmp.nx > 0 {
		var pad [BlockSize]byte
		copy(pad[:], tmp.buf[:tmp.nx])
		tmp.block(pad[:])
	}

	// Имитовставкой служат старшие разряды регистра N1; при длине в
	// четыре байта это регистр целиком.
	var out [BlockSize]byte
	binary.LittleEndian.PutUint32(out[0:4], tmp.n1)
	binary.LittleEndian.PutUint32(out[4:8], tmp.n2)
	return append(in, out[BlockSize/2-tmp.size:BlockSize/2]...)
}

// MAC вычисляет имитовставку за один вызов.
func MAC(key []byte, sbox *SBox, iv, data []byte, size int) ([]byte, error) {
	m, err := NewMAC(key, sbox, iv, size)
	if err != nil {
		return nil, err
	}
	m.Write(data)
	return m.Sum(nil), nil
}
