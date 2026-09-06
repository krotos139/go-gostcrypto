// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3410

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

// Арифметика в поле вычетов по модулю p без math/big.
//
// Элементы хранятся в форме Монтгомери — как value * R mod p, где
// R = 2^(64n), n — число машинных слов модуля. При таком представлении
// приведение по модулю после умножения выполняется сдвигами и сложениями
// вместо деления, которое и было основной стоимостью в math/big.
//
// Все операции выполняются за время, не зависящее от значений операндов:
// число слов фиксировано, условное вычитание модуля реализовано маской, а
// не переходом. С math/big такого добиться нельзя в принципе: он хранит
// переменное число слов, поэтому время операции зависит от величины
// значения.

// maxLimbs — наибольшее число слов: 512-битные кривые.
const maxLimbs = 8

// fe — элемент поля: слова от младшего к старшему. Значащими являются
// первые field.n слов.
type fe [maxLimbs]uint64

type field struct {
	n    int      // число слов модуля
	p    fe       // модуль
	pBig *big.Int // он же, для преобразований на границе API
	n0   uint64   // -p^-1 mod 2^64
	rr   fe       // R^2 mod p — множитель для перевода в форму Монтгомери
	one  fe       // R mod p — единица в форме Монтгомери

	// Полубайты показателя p-2 от старшего к младшему: обращение
	// вычисляется возведением в эту степень.
	invExp []uint8
}

// fillLimbs записывает значение v в слова z.
//
// Перевод идёт через байтовое представление, а не копированием слов
// big.Int напрямую: big.Word имеет размер машинного слова и на 32-битных
// платформах вдвое короче нашего лимба. Копирование один к одному давало
// бы там молча неверный результат.
func fillLimbs(z *fe, v *big.Int, n int) {
	*z = fe{}
	var buf [8 * maxLimbs]byte
	b := buf[:8*n]
	v.FillBytes(b) // старший разряд слева, дополнено нулями
	for i := 0; i < n; i++ {
		z[i] = binary.BigEndian.Uint64(b[8*(n-1-i):])
	}
}

// limbsToBig собирает целое из слов. Обратна fillLimbs и по той же
// причине работает через байты.
func limbsToBig(x *fe, n int) *big.Int {
	var buf [8 * maxLimbs]byte
	b := buf[:8*n]
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(b[8*(n-1-i):], x[i])
	}
	return new(big.Int).SetBytes(b)
}

func newField(p *big.Int) *field {
	n := (p.BitLen() + 63) / 64
	f := &field{n: n, pBig: new(big.Int).Set(p)}
	fillLimbs(&f.p, p, n)

	// n0 = -p^-1 mod 2^64. Итерация Ньютона удваивает точность на шаге:
	// начиная с верного значения по модулю 2, шести шагов хватает на 64
	// разряда. Модуль нечётен, поэтому обратный элемент существует.
	inv := uint64(1)
	for i := 0; i < 6; i++ {
		inv *= 2 - f.p[0]*inv
	}
	f.n0 = -inv

	r := new(big.Int).Lsh(big.NewInt(1), uint(64*n))
	r.Mod(r, p)
	fillLimbs(&f.one, r, n)

	rr := new(big.Int).Mul(r, r)
	rr.Mod(rr, p)
	fillLimbs(&f.rr, rr, n)

	e := new(big.Int).Sub(p, big.NewInt(2))
	nb := (e.BitLen() + 3) / 4
	f.invExp = make([]uint8, nb)
	for i := 0; i < nb; i++ {
		shift := uint(4 * (nb - 1 - i))
		f.invExp[i] = uint8(new(big.Int).Rsh(e, shift).Uint64() & 0xf)
	}
	return f
}

// condSubP записывает в z значение t - p, если t >= p, иначе t.
// Величина t занимает n+1 слов: старшее передаётся отдельно.
func (f *field) condSubP(z *fe, t *fe, top uint64) {
	var d fe
	var borrow uint64
	for j := 0; j < f.n; j++ {
		d[j], borrow = bits.Sub64(t[j], f.p[j], borrow)
	}
	_, borrow = bits.Sub64(top, 0, borrow)

	// borrow = 1 означает t < p: вычитать не нужно.
	keep := -borrow
	for j := 0; j < f.n; j++ {
		z[j] = (t[j] & keep) | (d[j] &^ keep)
	}
}

// mul вычисляет z = x * y * R^-1 mod p методом CIOS.
func (f *field) mul(z, x, y *fe) {
	n := f.n
	var t [maxLimbs + 2]uint64

	for i := 0; i < n; i++ {
		// t += x * y[i]
		var c uint64
		for j := 0; j < n; j++ {
			hi, lo := bits.Mul64(x[j], y[i])
			var cc uint64
			lo, cc = bits.Add64(lo, t[j], 0)
			hi += cc
			lo, cc = bits.Add64(lo, c, 0)
			hi += cc
			t[j] = lo
			c = hi
		}
		var cc uint64
		t[n], cc = bits.Add64(t[n], c, 0)
		t[n+1] = cc

		// t += m*p, после чего младшее слово t обнуляется и t сдвигается
		// на слово вправо.
		m := t[0] * f.n0
		hi, lo := bits.Mul64(m, f.p[0])
		_, cc = bits.Add64(lo, t[0], 0)
		c = hi + cc
		for j := 1; j < n; j++ {
			hi, lo := bits.Mul64(m, f.p[j])
			lo, cc = bits.Add64(lo, t[j], 0)
			hi += cc
			lo, cc = bits.Add64(lo, c, 0)
			hi += cc
			t[j-1] = lo
			c = hi
		}
		t[n-1], cc = bits.Add64(t[n], c, 0)
		t[n] = t[n+1] + cc
	}

	var r fe
	copy(r[:n], t[:n])
	f.condSubP(z, &r, t[n])
}

func (f *field) sqr(z, x *fe) { f.mul(z, x, x) }

func (f *field) add(z, x, y *fe) {
	var t fe
	var carry uint64
	for j := 0; j < f.n; j++ {
		t[j], carry = bits.Add64(x[j], y[j], carry)
	}
	f.condSubP(z, &t, carry)
}

func (f *field) sub(z, x, y *fe) {
	var t fe
	var borrow uint64
	for j := 0; j < f.n; j++ {
		t[j], borrow = bits.Sub64(x[j], y[j], borrow)
	}
	// При заёме прибавляем модуль обратно.
	add := -borrow
	var carry uint64
	for j := 0; j < f.n; j++ {
		z[j], carry = bits.Add64(t[j], f.p[j]&add, carry)
	}
}

// dbl вычисляет z = 2x.
func (f *field) dbl(z, x *fe) { f.add(z, x, x) }

// condMove копирует src в dst, если mask состоит из единиц, и оставляет
// dst без изменений, если mask нулевая. Промежуточных значений маска
// принимать не должна.
func (f *field) condMove(dst, src *fe, mask uint64) {
	for j := 0; j < f.n; j++ {
		dst[j] = (dst[j] &^ mask) | (src[j] & mask)
	}
}

// isZero сообщает, равен ли элемент нулю. Сравнение без ветвлений.
func (f *field) isZero(x *fe) bool {
	var acc uint64
	for j := 0; j < f.n; j++ {
		acc |= x[j]
	}
	return acc == 0
}

func (f *field) equal(x, y *fe) bool {
	var acc uint64
	for j := 0; j < f.n; j++ {
		acc |= x[j] ^ y[j]
	}
	return acc == 0
}

// toMont переводит целое в форму Монтгомери.
func (f *field) toMont(z *fe, v *big.Int) {
	var t fe
	r := v
	if r.Sign() < 0 || r.Cmp(f.pBig) >= 0 {
		r = new(big.Int).Mod(v, f.pBig)
	}
	fillLimbs(&t, r, f.n)
	f.mul(z, &t, &f.rr)
}

// fromMont возвращает обычное представление элемента.
func (f *field) fromMont(x *fe) *big.Int {
	var one, t fe
	one[0] = 1
	f.mul(&t, x, &one)
	return limbsToBig(&t, f.n)
}

// inv вычисляет z = x^-1 как x^(p-2): по малой теореме Ферма это обратный
// элемент, поскольку p простое.
//
// Показатель p-2 — открытая величина, одна и та же для всей кривой,
// поэтому последовательность операций и индексы в таблице от секретных
// данных не зависят. Обращение через math/big было бы быстрее, но его
// время зависит от значения аргумента, а аргумент здесь секретный:
// это координата Z, полученная из скаляра.
//
// Для нулевого аргумента возвращает ноль.
func (f *field) inv(z, x *fe) {
	var tbl [16]fe
	tbl[0] = f.one
	tbl[1] = *x
	for i := 2; i < 16; i++ {
		f.mul(&tbl[i], &tbl[i-1], x)
	}

	acc := f.one
	for i, nib := range f.invExp {
		if i > 0 {
			for j := 0; j < 4; j++ {
				f.sqr(&acc, &acc)
			}
		}
		f.mul(&acc, &acc, &tbl[nib])
	}
	*z = acc
}
