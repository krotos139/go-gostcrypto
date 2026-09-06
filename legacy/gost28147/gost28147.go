// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package gost28147 реализует блочный шифр ГОСТ 28147-89 (RFC 5830).
//
// # Устаревший алгоритм
//
// ГОСТ 28147-89 заменён на ГОСТ Р 34.12-2015: современный аналог этого
// шифра — "Магма" из пакета gost3412/magma. Здесь он нужен только для
// работы с ранее выпущенными документами и, главное, как составная часть
// хэш-функции ГОСТ Р 34.11-94. Для нового кода используйте "Магму" или
// "Кузнечика".
//
// # Отличия от "Магмы"
//
// Алгоритм тот же, но:
//
//   - ключ и данные разбираются как little-endian, а не big-endian;
//   - набор подстановок не зафиксирован стандартом, а является
//     параметром: RFC 5830 прямо отмечает, что S-блоки в нём не заданы.
//
// Из-за разного порядка байт совпадает не расписание ключей, а лишь
// структура: при одном и том же ключе "Магма" и этот шифр дают разные
// подключи и разный результат.
package gost28147

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/bits"
	"strconv"
)

const (
	// BlockSize — размер блока в байтах.
	BlockSize = 8
	// KeySize — размер ключа в байтах.
	KeySize = 32
	// SBoxSize — размер упакованного набора подстановок в байтах.
	SBoxSize = 64

	rounds = 32
)

// ErrSBox возвращается при некорректном наборе подстановок.
var ErrSBox = errors.New("gost28147: некорректный набор подстановок")

// KeySizeError возвращается NewCipher при неверной длине ключа.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "gost28147: неверный размер ключа " + strconv.Itoa(int(k))
}

// SBox — набор из восьми подстановок. SBox[0] применяется к младшему
// полубайту, SBox[7] — к старшему.
type SBox [8][16]byte

// Valid сообщает, является ли каждая из восьми таблиц перестановкой
// значений от 0 до 15.
func (s *SBox) Valid() bool {
	for _, t := range s {
		var seen [16]bool
		for _, v := range t {
			if v > 15 || seen[v] {
				return false
			}
			seen[v] = true
		}
	}
	return true
}

// UnpackSBox разбирает набор подстановок из 64 байт в том виде, в каком он
// записан в структурах ASN.1 (RFC 4357, раздел 11).
//
// Раскладка: 128 полубайт, старший в байте идёт первым; полубайт с
// номером n принадлежит подстановке n mod 8 и строке n div 8. То есть
// каждые четыре байта задают одну строку сразу всех восьми таблиц.
//
// Раскладка восстановлена по первоисточникам: при ней набор
// id-GostR3411-94-TestParamSet из RFC 4357 совпадает с таблицей
// подстановок из RFC 5831, п. 7.1, напечатанной явно.
func UnpackSBox(b []byte) (*SBox, error) {
	if len(b) != SBoxSize {
		return nil, ErrSBox
	}
	var s SBox
	for n := 0; n < 2*SBoxSize; n++ {
		v := b[n/2] >> 4
		if n%2 == 1 {
			v = b[n/2] & 0x0f
		}
		s[n%8][n/8] = v
	}
	if !s.Valid() {
		return nil, ErrSBox
	}
	return &s, nil
}

// Cipher — экземпляр шифра. Реализует cipher.Block; кроме того, у него
// можно сменить ключ, не пересобирая таблицы подстановок.
type Cipher struct {
	rk    [rounds]uint32
	table [4][256]uint32
}

var _ cipher.Block = (*Cipher)(nil)

// NewSchedule создаёт шифр с заданным набором подстановок и пока без
// ключа: таблицы подстановок зависят только от набора, поэтому их можно
// построить один раз и дальше менять ключ через SetKey.
//
// Это нужно хэш-функции ГОСТ Р 34.11-94, которая меняет ключ четырежды на
// каждый обрабатываемый блок: пересборка таблиц там обошлась бы дороже
// самого шифрования.
func NewSchedule(sbox *SBox) (*Cipher, error) {
	if sbox == nil || !sbox.Valid() {
		return nil, ErrSBox
	}
	c := new(Cipher)
	// Подстановка t и циклический сдвиг на 11 разрядов сворачиваются в
	// четыре таблицы: вклады разных байт не пересекаются, а сдвиг линеен
	// относительно XOR.
	for j := 0; j < 4; j++ {
		for x := 0; x < 256; x++ {
			v := uint32(sbox[2*j][x&0x0f]) | uint32(sbox[2*j+1][x>>4])<<4
			c.table[j][x] = bits.RotateLeft32(v<<(8*uint(j)), 11)
		}
	}
	return c, nil
}

// SetKey заменяет ключ шифра.
//
// X0 = key[0:4] в порядке от младшего байта, ..., X7 = key[28:32].
// Раунды 1-24 используют X0..X7 трижды, раунды 25-32 — в обратном порядке.
func (c *Cipher) SetKey(key []byte) error {
	if len(key) != KeySize {
		return KeySizeError(len(key))
	}
	var x [8]uint32
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	for i := 0; i < 24; i++ {
		c.rk[i] = x[i%8]
	}
	for i := 0; i < 8; i++ {
		c.rk[24+i] = x[7-i]
	}
	return nil
}

// NewCipher создаёт cipher.Block для ГОСТ 28147-89 с заданным ключом и
// набором подстановок.
func NewCipher(key []byte, sbox *SBox) (cipher.Block, error) {
	c, err := NewSchedule(sbox)
	if err != nil {
		return nil, err
	}
	if err := c.SetKey(key); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cipher) BlockSize() int { return BlockSize }

// f — основное шаговое преобразование: сложение с подключом по модулю
// 2^32, подстановка и циклический сдвиг на 11 разрядов влево.
func (c *Cipher) f(a, k uint32) uint32 {
	s := a + k
	return c.table[0][byte(s)] ^
		c.table[1][byte(s>>8)] ^
		c.table[2][byte(s>>16)] ^
		c.table[3][byte(s>>24)]
}

func (c *Cipher) crypt(dst, src []byte, decrypt bool) {
	if len(src) < BlockSize {
		panic("gost28147: короткий входной блок")
	}
	if len(dst) < BlockSize {
		panic("gost28147: короткий выходной блок")
	}
	n1 := binary.LittleEndian.Uint32(src[0:4])
	n2 := binary.LittleEndian.Uint32(src[4:8])

	// Раунды 1-31 меняют половины местами, раунд 32 — нет.
	for i := 0; i < rounds-1; i++ {
		j := i
		if decrypt {
			j = rounds - 1 - i
		}
		n1, n2 = n2^c.f(n1, c.rk[j]), n1
	}
	last := rounds - 1
	if decrypt {
		last = 0
	}
	n2 ^= c.f(n1, c.rk[last])

	binary.LittleEndian.PutUint32(dst[0:4], n1)
	binary.LittleEndian.PutUint32(dst[4:8], n2)
}

func (c *Cipher) Encrypt(dst, src []byte) { c.crypt(dst, src, false) }
func (c *Cipher) Decrypt(dst, src []byte) { c.crypt(dst, src, true) }
