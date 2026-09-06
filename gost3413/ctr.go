// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import "crypto/cipher"

// Режим гаммирования (ГОСТ Р 34.13-2015, 5.2):
//
//	CTR_1 = IV || 0^(n/2)
//	CTR_{i+1} = Vec_n(Int_n(CTR_i) [+] 1)
//	C_i = P_i xor T_s(e_K(CTR_i))
//
// Синхропосылка имеет длину n/2, а не n: младшая половина блока отведена
// под счётчик. Именно поэтому cipher.NewCTR из стандартной библиотеки
// здесь не подходит — он ожидает синхропосылку в целый блок и не умеет
// усекать гамму до s < n.

type ctrStream struct {
	b   cipher.Block
	bs  int
	s   int
	ctr []byte // текущее значение счётчика, n байт
	tmp []byte // выход базового алгоритма, n байт
	ks  []byte // текущий блок гаммы, s байт
	pos int    // позиция в ks; pos == s означает, что гамма исчерпана
}

// NewCTR возвращает cipher.Stream для режима гаммирования с s = n.
// Длина iv должна быть ровно n/2 байт.
func NewCTR(b cipher.Block, iv []byte) (cipher.Stream, error) {
	return NewCTRWithS(b, iv, b.BlockSize())
}

// NewCTRWithS возвращает cipher.Stream для режима гаммирования с заданным
// параметром s (в байтах, 0 < s <= n). Длина iv должна быть ровно n/2 байт.
func NewCTRWithS(b cipher.Block, iv []byte, s int) (cipher.Stream, error) {
	bs := b.BlockSize()
	if bs%2 != 0 {
		return nil, ErrBlockSize
	}
	if len(iv) != bs/2 {
		return nil, ErrIVSize
	}
	if s <= 0 || s > bs {
		return nil, ErrSParam
	}
	x := &ctrStream{
		b:   b,
		bs:  bs,
		s:   s,
		ctr: make([]byte, bs),
		tmp: make([]byte, bs),
		ks:  make([]byte, s),
	}
	copy(x.ctr, iv)
	x.pos = s // первая же операция выработает гамму
	return x, nil
}

// next вырабатывает очередной блок гаммы и увеличивает счётчик.
func (x *ctrStream) next() {
	x.b.Encrypt(x.tmp, x.ctr)
	copy(x.ks, x.tmp[:x.s])
	x.pos = 0

	// Add: инкремент всего блока как big-endian числа.
	for i := x.bs - 1; i >= 0; i-- {
		x.ctr[i]++
		if x.ctr[i] != 0 {
			break
		}
	}
}

func (x *ctrStream) XORKeyStream(dst, src []byte) {
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
