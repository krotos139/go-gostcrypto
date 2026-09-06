// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import "crypto/cipher"

// Режим простой замены с зацеплением (ГОСТ Р 34.13-2015, 5.4):
//
//	R_1 = IV
//	C_i = e_K(P_i xor MSB_n(R_i))
//	R_{i+1} = LSB_{m-n}(R_i) || C_i
//
// Параметр m — длина регистра сдвига, m = n*z при z >= 1; он задаётся
// длиной синхропосылки. При z = 1 режим совпадает с классическим CBC, при
// z > 1 очередной блок сцепляется не с предыдущим блоком шифртекста, а с
// блоком, отстоящим на z позиций назад.

type cbc struct {
	b       cipher.Block
	bs      int
	r       []byte // регистр сдвига длины m
	tmp     []byte
	decrypt bool
}

func newCBC(b cipher.Block, iv []byte, decrypt bool) (cipher.BlockMode, error) {
	bs := b.BlockSize()
	if len(iv) == 0 || len(iv)%bs != 0 {
		return nil, ErrIVSize
	}
	return &cbc{
		b:       b,
		bs:      bs,
		r:       dup(iv),
		tmp:     make([]byte, bs),
		decrypt: decrypt,
	}, nil
}

// NewCBCEncrypter возвращает cipher.BlockMode, зашифровывающий в режиме
// простой замены с зацеплением. Длина iv задаёт параметр m и должна быть
// положительным кратным размеру блока.
func NewCBCEncrypter(b cipher.Block, iv []byte) (cipher.BlockMode, error) {
	return newCBC(b, iv, false)
}

// NewCBCDecrypter возвращает cipher.BlockMode, расшифровывающий в режиме
// простой замены с зацеплением.
func NewCBCDecrypter(b cipher.Block, iv []byte) (cipher.BlockMode, error) {
	return newCBC(b, iv, true)
}

func (x *cbc) BlockSize() int { return x.bs }

// shift сдвигает регистр на блок влево и дописывает блок шифртекста в
// младшие разряды: R_{i+1} = LSB_{m-n}(R_i) || C_i.
func (x *cbc) shift(ct []byte) {
	copy(x.r, x.r[x.bs:])
	copy(x.r[len(x.r)-x.bs:], ct)
}

func (x *cbc) CryptBlocks(dst, src []byte) {
	if len(src)%x.bs != 0 {
		panic("gost3413: длина сообщения не кратна размеру блока")
	}
	if len(dst) < len(src) {
		panic("gost3413: выходной буфер короче входного")
	}
	for len(src) > 0 {
		if x.decrypt {
			// P_i = d_K(C_i) xor MSB_n(R_i); регистр питается шифртекстом,
			// поэтому исходный блок сохраняется до записи в dst.
			copy(x.tmp, src[:x.bs])
			x.b.Decrypt(dst[:x.bs], src[:x.bs])
			xorBytes(dst, dst, x.r, x.bs)
			x.shift(x.tmp)
		} else {
			xorBytes(x.tmp, src, x.r, x.bs)
			x.b.Encrypt(dst[:x.bs], x.tmp)
			x.shift(dst[:x.bs])
		}
		src = src[x.bs:]
		dst = dst[x.bs:]
	}
}
