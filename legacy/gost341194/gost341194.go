// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package gost341194 реализует хэш-функцию ГОСТ Р 34.11-94 (RFC 5831).
//
// # Устаревший алгоритм
//
// ГОСТ Р 34.11-94 заменён на ГОСТ Р 34.11-2012 ("Стрибог", пакет
// gost3411/streebog). Здесь он нужен только для проверки ранее выпущенных
// документов: в старом документообороте он встречается в паре с подписью
// по ГОСТ Р 34.10-2001. Для нового кода используйте "Стрибог".
//
// Стойкость к поиску коллизий у этой функции ниже заявленной: известны
// методы, снижающие оценку с 2^128 примерно до 2^105 операций (об этом
// говорит и раздел 8 RFC 5831). Считать её пригодной для новых подписей
// нельзя.
//
// # Параметры
//
// Функция зависит от двух параметров: набора подстановок для ГОСТ 28147-89
// и начального значения h0. На практике почти всегда используется
// id-GostR3411-94-CryptoProParamSet с нулевым h0 — его возвращает
// NewCryptoPro.
//
// # Порядок байт
//
// Как и у "Стрибога", все векторы в стандарте напечатаны развёрнутыми
// относительно потока данных: контрольное сообщение "73657479 62203233 ..."
// из RFC 5831 — это ASCII-строка "This is message, length=32 bytes",
// записанная задом наперёд. Здесь состояние хранится байтами от младшего к
// старшему, поэтому байты потока ложатся в него напрямую, а хэш выдаётся в
// том же порядке индексов.
package gost341194

import (
	"encoding/binary"
	"hash"

	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

const (
	// Size — длина хэш-кода в байтах.
	Size = 32
	// BlockSize — размер блока в байтах.
	BlockSize = 32
)

// vec — вектор из V_256. Индекс 0 хранит младший байт, то есть первый байт
// потока.
type vec [Size]byte

// c3 — итерационная константа C[3] из п. 5.1 стандарта:
//
//	1^8||0^8||1^16||0^24||1^16||0^8||(0^8||1^8)^2||1^8||0^8
//	||(0^8||1^8)^4||(1^8||0^8)^4
//
// Запись идёт от старших разрядов к младшим, поэтому в vec она ложится
// в обратном порядке байт. Константы C[2] и C[4] нулевые.
var c3 = func() vec {
	msbFirst := []byte{
		0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
		0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
		0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
		0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
	}
	var v vec
	for i, b := range msbFirst {
		v[Size-1-i] = b
	}
	return v
}()

// permP — перестановка P из п. 5.1: результат на позиции 4k+i берёт байт
// с позиции 8i+k, k = 0..7, i = 0..3.
var permP = func() [Size]byte {
	var p [Size]byte
	for k := 0; k < 8; k++ {
		for i := 0; i < 4; i++ {
			p[4*k+i] = byte(8*i + k)
		}
	}
	return p
}()

// transformA: A(X) = (x1 xor x2)||x4||x3||x2, где x1 — младшие 64 разряда.
// В представлении vec это сдвиг на восемь байт вниз с дописыванием
// x1 xor x2 сверху.
func transformA(x vec) vec {
	var out vec
	copy(out[:24], x[8:])
	for i := 0; i < 8; i++ {
		out[24+i] = x[i] ^ x[8+i]
	}
	return out
}

func transformP(x vec) vec {
	var out vec
	for i := range out {
		out[i] = x[permP[i]]
	}
	return out
}

// psi — сдвиговый регистр из п. 5.3: старшее 16-разрядное слово результата
// равно сумме по модулю 2 слов 1, 2, 3, 4, 13 и 16, остальные сдвигаются.
func psi(x vec) vec {
	var out vec
	copy(out[:30], x[2:])
	out[30] = x[0] ^ x[2] ^ x[4] ^ x[6] ^ x[24] ^ x[30]
	out[31] = x[1] ^ x[3] ^ x[5] ^ x[7] ^ x[25] ^ x[31]
	return out
}

func xorVec(a, b vec) vec {
	var out vec
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

type digest struct {
	h     vec
	init  vec // начальное значение h0, нужно для Reset
	sigma vec
	l     vec // длина обработанного сообщения в битах
	buf   [BlockSize]byte
	nx    int
	c     *gost28147.Cipher
}

var _ hash.Hash = (*digest)(nil)

// New создаёт хэш-функцию с заданным набором подстановок для ГОСТ 28147-89
// и начальным значением h0.
func New(sbox *gost28147.SBox, h0 []byte) (hash.Hash, error) {
	c, err := gost28147.NewSchedule(sbox)
	if err != nil {
		return nil, err
	}
	d := &digest{c: c}
	if len(h0) == Size {
		copy(d.h[:], h0)
	}
	d.init = d.h
	d.Reset()
	return d, nil
}

// NewCryptoPro создаёт хэш-функцию с параметрами
// id-GostR3411-94-CryptoProParamSet и нулевым начальным значением — тем
// набором, который встречается в реальных документах.
func NewCryptoPro() hash.Hash {
	h, err := New(gost28147.ParamHashCryptoPro(), nil)
	if err != nil {
		panic("gost341194: " + err.Error())
	}
	return h
}

// NewTest создаёт хэш-функцию с параметрами id-GostR3411-94-TestParamSet и
// нулевым начальным значением. Предназначена только для проверки
// реализации: именно на этих подстановках построены контрольные примеры
// RFC 5831.
func NewTest() hash.Hash {
	h, err := New(gost28147.ParamHashTest(), nil)
	if err != nil {
		panic("gost341194: " + err.Error())
	}
	return h
}

func (d *digest) Size() int      { return Size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	d.h = d.init
	d.sigma = vec{}
	d.l = vec{}
	d.buf = [BlockSize]byte{}
	d.nx = 0
}

// keys вырабатывает четыре ключа шифрования по п. 5.1.
func (d *digest) keys(m vec) [4]vec {
	var k [4]vec
	u, v := d.h, m
	k[0] = transformP(xorVec(u, v))
	for i := 1; i < 4; i++ {
		u = transformA(u)
		if i == 2 { // C[3]; C[2] и C[4] нулевые
			u = xorVec(u, c3)
		}
		v = transformA(transformA(v))
		k[i] = transformP(xorVec(u, v))
	}
	return k
}

// chi вычисляет шаговую хэш-функцию chi(m, h) = psi^61(h xor psi(m xor psi^12(s))).
func (d *digest) chi(m vec) {
	k := d.keys(m)

	// s_i = E(K_i, h_i), где h_i — i-е 64-разрядное подслово H.
	var s vec
	for i := 0; i < 4; i++ {
		if err := d.c.SetKey(k[i][:]); err != nil {
			panic("gost341194: " + err.Error())
		}
		d.c.Encrypt(s[8*i:8*(i+1)], d.h[8*i:8*(i+1)])
	}

	for i := 0; i < 12; i++ {
		s = psi(s)
	}
	s = psi(xorVec(m, s))
	s = xorVec(d.h, s)
	for i := 0; i < 61; i++ {
		s = psi(s)
	}
	d.h = s
}

// addVec складывает 256-разрядные числа по модулю 2^256.
func addVec(a *vec, b *vec) {
	var carry uint16
	for i := 0; i < Size; i++ {
		sum := uint16(a[i]) + uint16(b[i]) + carry
		a[i] = byte(sum)
		carry = sum >> 8
	}
}

func addBits(a *vec, bits uint64) {
	var b vec
	binary.LittleEndian.PutUint64(b[:8], bits)
	addVec(a, &b)
}

// block выполняет шаг 3 стандарта для полного блока.
func (d *digest) block(p []byte) {
	var m vec
	copy(m[:], p)
	d.chi(m)
	addBits(&d.l, BlockSize*8)
	addVec(&d.sigma, &m)
}

func (d *digest) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		// Полный блок обрабатывается только тогда, когда за ним есть
		// ещё данные: последний блок, даже полный, идёт через шаг 2.
		if d.nx == BlockSize {
			d.block(d.buf[:])
			d.nx = 0
		}
		k := copy(d.buf[d.nx:], p)
		d.nx += k
		p = p[k:]
	}
	return total, nil
}

// Sum дописывает хэш-код к in, не изменяя состояние.
func (d *digest) Sum(in []byte) []byte {
	tmp := *d
	// Шифр разделяется между копиями, но состояние ключа переустанавливается
	// перед каждым использованием, поэтому это безопасно.
	return append(in, tmp.checkSum()...)
}

// checkSum выполняет шаг 2 стандарта: дополнение нулями, накопление длины
// и контрольной суммы, затем две завершающие свёртки.
func (d *digest) checkSum() []byte {
	var m vec
	copy(m[:], d.buf[:d.nx])

	addBits(&d.l, uint64(d.nx)*8)
	addVec(&d.sigma, &m)
	d.chi(m)
	d.chi(d.l)
	d.chi(d.sigma)

	out := d.h
	return out[:]
}

// Sum256 вычисляет хэш-код с параметрами CryptoPro за один вызов.
func Sum256(data []byte) [Size]byte {
	h := NewCryptoPro()
	h.Write(data)
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
