// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import "crypto/cipher"

// Режим простой замены (ГОСТ Р 34.13-2015, 5.1): C_i = e_K(P_i).
//
// Синхропосылка не используется, одинаковые блоки открытого текста дают
// одинаковые блоки шифртекста. Длина сообщения должна быть кратна размеру
// блока — при необходимости примените одну из процедур дополнения.

type ecb struct {
	b       cipher.Block
	bs      int
	decrypt bool
}

func newECB(b cipher.Block, decrypt bool) cipher.BlockMode {
	return &ecb{b: b, bs: b.BlockSize(), decrypt: decrypt}
}

// NewECBEncrypter возвращает cipher.BlockMode, зашифровывающий в режиме
// простой замены.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode { return newECB(b, false) }

// NewECBDecrypter возвращает cipher.BlockMode, расшифровывающий в режиме
// простой замены.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode { return newECB(b, true) }

func (x *ecb) BlockSize() int { return x.bs }

func (x *ecb) CryptBlocks(dst, src []byte) {
	if len(src)%x.bs != 0 {
		panic("gost3413: длина сообщения не кратна размеру блока")
	}
	if len(dst) < len(src) {
		panic("gost3413: выходной буфер короче входного")
	}
	for len(src) > 0 {
		if x.decrypt {
			x.b.Decrypt(dst[:x.bs], src[:x.bs])
		} else {
			x.b.Encrypt(dst[:x.bs], src[:x.bs])
		}
		src = src[x.bs:]
		dst = dst[x.bs:]
	}
}
