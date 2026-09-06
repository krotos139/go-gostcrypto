// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import "crypto/cipher"

// Режим гаммирования с обратной связью по выходу
// (ГОСТ Р 34.13-2015, 5.3):
//
//	R_1 = IV
//	Y_i = e_K(MSB_n(R_i))
//	C_i = P_i xor T_s(Y_i)
//	R_{i+1} = LSB_{m-n}(R_i) || Y_i
//
// Параметр m — длина регистра сдвига, m = n*z при z >= 1; он задаётся
// длиной синхропосылки. При z = 1 режим совпадает с классическим OFB.

type ofbStream struct {
	b   cipher.Block
	bs  int
	s   int
	r   []byte // регистр сдвига длины m
	tmp []byte // выход базового алгоритма, n байт
	ks  []byte // текущий блок гаммы, s байт
	pos int
}

// NewOFB возвращает cipher.Stream для режима гаммирования с обратной
// связью по выходу с s = n. Длина iv задаёт m и должна быть положительным
// кратным размеру блока.
func NewOFB(b cipher.Block, iv []byte) (cipher.Stream, error) {
	return NewOFBWithS(b, iv, b.BlockSize())
}

// NewOFBWithS возвращает cipher.Stream для того же режима с заданным
// параметром s (в байтах, 0 < s <= n).
func NewOFBWithS(b cipher.Block, iv []byte, s int) (cipher.Stream, error) {
	bs := b.BlockSize()
	if len(iv) == 0 || len(iv)%bs != 0 {
		return nil, ErrIVSize
	}
	if s <= 0 || s > bs {
		return nil, ErrSParam
	}
	x := &ofbStream{
		b:   b,
		bs:  bs,
		s:   s,
		r:   dup(iv),
		tmp: make([]byte, bs),
		ks:  make([]byte, s),
	}
	x.pos = s
	return x, nil
}

func (x *ofbStream) next() {
	x.b.Encrypt(x.tmp, x.r[:x.bs])
	copy(x.ks, x.tmp[:x.s])
	x.pos = 0

	// R_{i+1} = LSB_{m-n}(R_i) || Y_i
	copy(x.r, x.r[x.bs:])
	copy(x.r[len(x.r)-x.bs:], x.tmp)
}

func (x *ofbStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost3413: выходной буфер короче входного")
	}
	for len(src) > 0 {
		if x.pos == x.s {
			x.next()
		}
		n := min(x.s-x.pos, len(src))
		xorBytes(dst, src, x.ks[x.pos:], n)
		x.pos += n
		src, dst = src[n:], dst[n:]
	}
}
