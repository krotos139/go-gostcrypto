// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost28147

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unsafe"
)

// Режимы гаммирования ГОСТ 28147-89 (RFC 5830, разделы 6 и 7).
//
// Оба режима превращают шифр в поточный: гамма складывается с текстом по
// модулю 2, поэтому длина сообщения произвольна, а зашифрование и
// расшифрование в режиме гаммирования — одно и то же преобразование.
//
// Эти режимы устарели вместе с самим шифром. Для нового кода нужны
// режимы из ГОСТ Р 34.13-2015 (пакет gost3413) поверх "Магмы" или
// "Кузнечика".

// Константы из приложения A к RFC 5830.
const (
	c1 = 0x01010104 // прибавляется к N4 по модулю 2^32-1
	c2 = 0x01010101 // прибавляется к N3 по модулю 2^32
)

// ErrBlockSize возвращается, если размер блока шифра не равен восьми
// байтам: режимы этого раздела определены только для ГОСТ 28147-89.
var ErrBlockSize = errors.New("gost28147: размер блока должен быть 8 байт")

// addMod32m1 складывает по модулю 2^32-1: результат уменьшается на
// 2^32-1, если сумма достигла этого значения (RFC 5830, раздел 4).
func addMod32m1(a, b uint32) uint32 {
	s := uint64(a) + uint64(b)
	if s >= 0xFFFFFFFF {
		s -= 0xFFFFFFFF
	}
	return uint32(s)
}

// gammaStream — режим гаммирования (RFC 5830, раздел 6).
type gammaStream struct {
	c      cipher.Block
	y, z   uint32
	gamma  [BlockSize]byte
	unused int // сколько байт гаммы осталось в конце буфера
}

// NewGamma создаёт поточный шифр в режиме гаммирования.
//
// Гамма не зависит от текста, поэтому одно и то же преобразование и
// зашифровывает, и расшифровывает. Синхропосылка iv занимает блок и при
// одном ключе не должна повторяться: повтор раскрывает сумму двух
// сообщений по модулю 2.
func NewGamma(b cipher.Block, iv []byte) (cipher.Stream, error) {
	if b.BlockSize() != BlockSize {
		return nil, ErrBlockSize
	}
	if len(iv) != BlockSize {
		return nil, ErrIVSize
	}
	// (Y0, Z0) = A(S): синхропосылка зашифровывается в режиме простой
	// замены, результат становится начальным состоянием счётчика.
	var s [BlockSize]byte
	b.Encrypt(s[:], iv)
	return &gammaStream{
		c: b,
		y: binary.LittleEndian.Uint32(s[0:4]),
		z: binary.LittleEndian.Uint32(s[4:8]),
	}, nil
}

// next вырабатывает очередной блок гаммы.
func (g *gammaStream) next() {
	g.y += c2
	g.z = addMod32m1(g.z, c1)
	var in [BlockSize]byte
	binary.LittleEndian.PutUint32(in[0:4], g.y)
	binary.LittleEndian.PutUint32(in[4:8], g.z)
	g.c.Encrypt(g.gamma[:], in[:])
	g.unused = BlockSize
}

func (g *gammaStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost28147: короткий приёмник")
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("gost28147: недопустимое перекрытие буферов")
	}
	for len(src) > 0 {
		if g.unused == 0 {
			g.next()
		}
		off := BlockSize - g.unused
		n := len(src)
		if n > g.unused {
			n = g.unused
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ g.gamma[off+i]
		}
		g.unused -= n
		dst, src = dst[n:], src[n:]
	}
}

// cfbStream — гаммирование с обратной связью (RFC 5830, раздел 7).
type cfbStream struct {
	c       cipher.Block
	state   [BlockSize]byte // предыдущий блок шифртекста, для первого — синхропосылка
	gamma   [BlockSize]byte
	unused  int
	decrypt bool
	// feed накапливает шифртекст текущего блока: он и уходит в обратную
	// связь, поэтому его приходится собирать отдельно от dst, который
	// при расшифровании содержит открытый текст.
	feed [BlockSize]byte
}

// NewCFBEncrypter создаёт зашифрование в режиме гаммирования с обратной
// связью (RFC 5830, раздел 7).
//
// В отличие от режима гаммирования, здесь обратная связь идёт по
// шифртексту, поэтому зашифрование и расшифрование — разные функции.
func NewCFBEncrypter(b cipher.Block, iv []byte) (cipher.Stream, error) {
	return newCFB(b, iv, false)
}

// NewCFBDecrypter создаёт расшифрование в режиме гаммирования с обратной
// связью (RFC 5830, раздел 7).
func NewCFBDecrypter(b cipher.Block, iv []byte) (cipher.Stream, error) {
	return newCFB(b, iv, true)
}

func newCFB(b cipher.Block, iv []byte, decrypt bool) (cipher.Stream, error) {
	if b.BlockSize() != BlockSize {
		return nil, ErrBlockSize
	}
	if len(iv) != BlockSize {
		return nil, ErrIVSize
	}
	s := &cfbStream{c: b, decrypt: decrypt}
	copy(s.state[:], iv)
	return s, nil
}

func (s *cfbStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost28147: короткий приёмник")
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("gost28147: недопустимое перекрытие буферов")
	}
	for len(src) > 0 {
		if s.unused == 0 {
			// Gc(i) = A(Tc(i-1)); для первого блока Tc(0) = S.
			s.c.Encrypt(s.gamma[:], s.state[:])
			s.unused = BlockSize
		}
		off := BlockSize - s.unused
		n := len(src)
		if n > s.unused {
			n = s.unused
		}
		for i := 0; i < n; i++ {
			// В обратную связь всегда уходит шифртекст.
			if s.decrypt {
				s.feed[off+i] = src[i]
			} else {
				s.feed[off+i] = src[i] ^ s.gamma[off+i]
			}
			dst[i] = src[i] ^ s.gamma[off+i]
		}
		s.unused -= n
		if s.unused == 0 {
			s.state = s.feed
		}
		dst, src = dst[n:], src[n:]
	}
}

// inexactOverlap сообщает, перекрываются ли срезы иначе, чем начинаясь с
// одного адреса: шифрование "на месте" допустимо, частичное наложение
// молча испортило бы данные.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}
