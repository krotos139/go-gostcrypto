// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package kdf

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"

	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
)

// PBKDF2 вырабатывает ключ длины keyLen байт из пароля и соли по схеме
// PBKDF2 (PKCS#5 v2.1) с псевдослучайной функцией
// HMAC_GOSTR3411_2012_512, как предписывает Р 50.1.111-2016.
//
// Пароль подаётся в кодировке UTF-8 без завершающего нуля.
//
// PBKDF2 замедляет перебор ровно во столько раз, во сколько велик iter, и
// не более того: это не защита от подбора слабого пароля, а лишь
// удорожание перебора. Число итераций стоит выбирать максимальным из
// приемлемых по времени.
func PBKDF2(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2(password, salt, iter, keyLen, streebog.New512)
}

// PBKDF2With256 — тот же алгоритм на HMAC_GOSTR3411_2012_256.
// Р 50.1.111-2016 предписывает 512-битный вариант; этот нужен только для
// совместимости с системами, где выбран 256-битный.
func PBKDF2With256(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2(password, salt, iter, keyLen, streebog.New256)
}

func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen

	out := make([]byte, 0, blocks*hLen)
	u := make([]byte, 0, hLen)
	t := make([]byte, hLen)
	var idx [4]byte

	for block := 1; block <= blocks; block++ {
		// U_1 = PRF(P, S || INT(block))
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf.Write(idx[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		// U_j = PRF(P, U_{j-1}); T = U_1 xor ... xor U_iter
		for j := 2; j <= iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
