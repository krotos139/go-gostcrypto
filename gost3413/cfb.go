// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import "crypto/cipher"

// Режим гаммирования с обратной связью по шифртексту
// (ГОСТ Р 34.13-2015, 5.5):
//
//	R_1 = IV
//	C_i = P_i xor T_s(e_K(MSB_n(R_i)))
//	R_{i+1} = LSB_{m-s}(R_i) || C_i
//
// Параметры: s (размер блока гаммы) и m (длина регистра сдвига), n <= m.
// В отличие от OFB регистр сдвигается на s, а не на n, и питается
// шифртекстом — поэтому зашифрование и расшифрование не совпадают и
// создаются разными конструкторами.

type cfbStream struct {
	b       cipher.Block
	bs      int
	s       int
	r       []byte // регистр сдвига длины m
	tmp     []byte // выход базового алгоритма, n байт
	ks      []byte // текущий блок гаммы, s байт
	fb      []byte // накопленный блок шифртекста для обратной связи, s байт
	pos     int
	decrypt bool
}

func newCFB(b cipher.Block, iv []byte, s int, decrypt bool) (cipher.Stream, error) {
	bs := b.BlockSize()
	if len(iv) < bs {
		return nil, ErrIVSize
	}
	if s <= 0 || s > bs || s > len(iv) {
		return nil, ErrSParam
	}
	return &cfbStream{
		b:       b,
		bs:      bs,
		s:       s,
		r:       dup(iv),
		tmp:     make([]byte, bs),
		ks:      make([]byte, s),
		fb:      make([]byte, s),
		decrypt: decrypt,
	}, nil
}

// NewCFBEncrypter возвращает cipher.Stream, зашифровывающий в режиме
// гаммирования с обратной связью по шифртексту с s = n. Длина iv задаёт m
// и должна быть не меньше размера блока.
func NewCFBEncrypter(b cipher.Block, iv []byte) (cipher.Stream, error) {
	return newCFB(b, iv, b.BlockSize(), false)
}

// NewCFBDecrypter возвращает cipher.Stream, расшифровывающий в том же
// режиме с s = n.
func NewCFBDecrypter(b cipher.Block, iv []byte) (cipher.Stream, error) {
	return newCFB(b, iv, b.BlockSize(), true)
}

// NewCFBEncrypterWithS — то же, что NewCFBEncrypter, с явным параметром s
// (в байтах, 0 < s <= n).
func NewCFBEncrypterWithS(b cipher.Block, iv []byte, s int) (cipher.Stream, error) {
	return newCFB(b, iv, s, false)
}

// NewCFBDecrypterWithS — то же, что NewCFBDecrypter, с явным параметром s.
func NewCFBDecrypterWithS(b cipher.Block, iv []byte, s int) (cipher.Stream, error) {
	return newCFB(b, iv, s, true)
}

func (x *cfbStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost3413: выходной буфер короче входного")
	}
	for len(src) > 0 {
		if x.pos == 0 {
			x.b.Encrypt(x.tmp, x.r[:x.bs])
			copy(x.ks, x.tmp[:x.s])
		}

		k := min(x.s-x.pos, len(src))
		for i := 0; i < k; i++ {
			// src читается до записи в dst: буферы могут совпадать.
			out := src[i] ^ x.ks[x.pos+i]
			// В обратную связь всегда уходит шифртекст: при зашифровании
			// это результат, при расшифровании — исходный байт.
			if x.decrypt {
				x.fb[x.pos+i] = src[i]
			} else {
				x.fb[x.pos+i] = out
			}
			dst[i] = out
		}
		x.pos += k
		src = src[k:]
		dst = dst[k:]

		if x.pos == x.s {
			// R_{i+1} = LSB_{m-s}(R_i) || C_i
			copy(x.r, x.r[x.s:])
			copy(x.r[len(x.r)-x.s:], x.fb)
			x.pos = 0
		}
	}
}
