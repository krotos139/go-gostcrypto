// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/krotos139/go-gostcrypto/gost3413"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

// Заворачивание ключа по алгоритмам RFC 4357, пп. 6.1-6.5.
//
// Это то, что применяется в зашифрованных сообщениях CMS отечественного
// профиля (RFC 4490): ключ шифрования содержимого заворачивается на
// ключе, выработанном алгоритмом ВКО.
//
// От схемы из RFC 7836, п. 4.6 (функции Wrap и Unwrap этого пакета) она
// отличается способом получения рабочего ключа: там KDF на «Стрибоге»,
// здесь — диверсификация значением UKM по п. 6.5.

const (
	// UKMSize — длина значения UKM.
	UKMSize = 8
	// WrappedSize — длина завёрнутого ключа: UKM, шифртекст и имитовставка.
	WrappedSize = UKMSize + gost28147.KeySize + MACSize
)

// DiversifyKEK вырабатывает ключ K(UKM) из ключа kek и значения ukm
// (RFC 4357, п. 6.5).
//
// Восемь раз подряд ключ пропускается через режим гаммирования с
// обратной связью, где синхропосылка складывается из сумм слов ключа,
// отобранных битами очередного байта UKM.
func DiversifyKEK(kek, ukm []byte, sbox *gost28147.SBox) ([]byte, error) {
	if len(kek) != gost28147.KeySize {
		return nil, ErrKeySize
	}
	if len(ukm) != UKMSize {
		return nil, ErrSeedSize
	}

	k := make([]byte, gost28147.KeySize)
	copy(k, kek)

	var words [8]uint32
	for i := 0; i < UKMSize; i++ {
		for j := 0; j < 8; j++ {
			words[j] = binary.LittleEndian.Uint32(k[j*4 : j*4+4])
		}

		// S = (сумма слов по единичным битам) | (сумма по нулевым),
		// обе по модулю 2^32.
		var sOnes, sZeros uint32
		for j := 0; j < 8; j++ {
			if ukm[i]>>uint(j)&1 == 1 {
				sOnes += words[j]
			} else {
				sZeros += words[j]
			}
		}
		var s [gost28147.BlockSize]byte
		binary.LittleEndian.PutUint32(s[0:4], sOnes)
		binary.LittleEndian.PutUint32(s[4:8], sZeros)

		// K[i+1] = encryptCFB(S, K[i], K[i]): ключ шифрует сам себя.
		b, err := gost28147.NewCipher(k, sbox)
		if err != nil {
			return nil, err
		}
		st, err := gost28147.NewCFBEncrypter(b, s[:])
		if err != nil {
			return nil, err
		}
		next := make([]byte, gost28147.KeySize)
		st.XORKeyStream(next, k)
		k = next
	}
	return k, nil
}

// WrapCryptoPro заворачивает ключ шифрования содержимого cek на ключе
// kek (RFC 4357, п. 6.3).
//
// Значение ukm должно быть тем же, на котором вырабатывался kek через
// ВКО. Результат имеет вид UKM || CEK_ENC || CEK_MAC.
func WrapCryptoPro(kek, ukm, cek []byte, sbox *gost28147.SBox) ([]byte, error) {
	if len(ukm) != UKMSize {
		return nil, ErrSeedSize
	}
	if len(cek) != gost28147.KeySize {
		return nil, ErrKeySize
	}

	dk, err := DiversifyKEK(kek, ukm, sbox)
	if err != nil {
		return nil, err
	}
	return wrapWith(dk, ukm, cek, sbox)
}

// WrapGOST заворачивает ключ без диверсификации (RFC 4357, п. 6.1).
//
// Годится только для ключей, уникальных для каждой пары отправитель -
// получатель: сам стандарт запрещает применять его к ключу, выработанному
// ВКО ГОСТ Р 34.10-94, который для такой пары постоянен.
func WrapGOST(kek, ukm, cek []byte, sbox *gost28147.SBox) ([]byte, error) {
	if len(ukm) != UKMSize {
		return nil, ErrSeedSize
	}
	if len(cek) != gost28147.KeySize {
		return nil, ErrKeySize
	}
	if len(kek) != gost28147.KeySize {
		return nil, ErrKeySize
	}
	return wrapWith(kek, ukm, cek, sbox)
}

func wrapWith(key, ukm, cek []byte, sbox *gost28147.SBox) ([]byte, error) {
	mac, err := gost28147.MAC(key, sbox, ukm, cek, MACSize)
	if err != nil {
		return nil, err
	}
	b, err := gost28147.NewCipher(key, sbox)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(cek))
	gost3413.NewECBEncrypter(b).CryptBlocks(enc, cek)

	out := make([]byte, 0, WrappedSize)
	out = append(out, ukm...)
	out = append(out, enc...)
	out = append(out, mac...)
	return out, nil
}

// UnwrapCryptoPro восстанавливает ключ шифрования содержимого
// (RFC 4357, п. 6.4).
func UnwrapCryptoPro(kek, wrapped []byte, sbox *gost28147.SBox) ([]byte, error) {
	if len(wrapped) != WrappedSize {
		return nil, ErrMalformed
	}
	dk, err := DiversifyKEK(kek, wrapped[:UKMSize], sbox)
	if err != nil {
		return nil, err
	}
	return unwrapWith(dk, wrapped, sbox)
}

// UnwrapGOST восстанавливает ключ, завёрнутый без диверсификации
// (RFC 4357, п. 6.2).
func UnwrapGOST(kek, wrapped []byte, sbox *gost28147.SBox) ([]byte, error) {
	if len(wrapped) != WrappedSize {
		return nil, ErrMalformed
	}
	if len(kek) != gost28147.KeySize {
		return nil, ErrKeySize
	}
	return unwrapWith(kek, wrapped, sbox)
}

func unwrapWith(key, wrapped []byte, sbox *gost28147.SBox) ([]byte, error) {
	ukm := wrapped[:UKMSize]
	enc := wrapped[UKMSize : UKMSize+gost28147.KeySize]
	gotMAC := wrapped[UKMSize+gost28147.KeySize:]

	b, err := gost28147.NewCipher(key, sbox)
	if err != nil {
		return nil, err
	}
	cek := make([]byte, len(enc))
	gost3413.NewECBDecrypter(b).CryptBlocks(cek, enc)

	wantMAC, err := gost28147.MAC(key, sbox, ukm, cek, MACSize)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(wantMAC, gotMAC) != 1 {
		return nil, ErrMAC
	}
	return cek, nil
}
