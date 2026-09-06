// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
	"github.com/krotos139/go-gostcrypto/gost3413"
)

// Контрольные примеры из приложения Б к Р 1323565.1.017-2018.
//
// Входные данные общие для обоих шифров, различаются синхропосылка и
// результат.
const (
	kexpKeyHex = "8899AABBCCDDEEFF0011223344556677" +
		"FEDCBA98765432100123456789ABCDEF"
	kexpMACKeyHex = "08090A0B0C0D0E0F0001020304050607" +
		"101112131415161718191A1B1C1D1E1F"
	kexpENCKeyHex = "202122232425262728292A2B2C2D2E2F" +
		"38393A3B3C3D3E3F3031323334353637"

	// Б.1, «Магма»: n = 64 бита, синхропосылка 4 байта.
	magmaIVHex     = "67BED654"
	magmaKEYMACHex = "75A76618E90F4973"
	magmaKEXPHex   = "CFD5A12D5B81B6E1E99C916D07900C6A" +
		"C12703FB3ABDED55567BF3742C899C75" +
		"5DAFE7B42E3A8BD9"

	// Б.2, «Кузнечик»: n = 128 бит, синхропосылка 8 байт.
	kuzIVHex     = "0909472DD9F26BE8"
	kuzKEYMACHex = "10022ADE94EE55B434D2077F5A13AFF4"
	kuzKEXPHex   = "E36184E84E8D736FF36CC2E5AE065DC6" +
		"56B23C20F549B02FDFF88E1F3F30D8C2" +
		"9A53F3CA554DBAD80DE152B9A4625B32"
)

func hx(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex: %v", err)
	}
	return b
}

// newVectorCiphers создаёт пару шифров на ключах из примера.
func newVectorCiphers(t testing.TB, useMagma bool, kMAC, kENC []byte) (cipher.Block, cipher.Block) {
	t.Helper()
	var (
		mc, ec cipher.Block
		err    error
	)
	if useMagma {
		mc, err = magma.NewCipher(kMAC)
		if err != nil {
			t.Fatal(err)
		}
		ec, err = magma.NewCipher(kENC)
	} else {
		mc, err = kuznyechik.NewCipher(kMAC)
		if err != nil {
			t.Fatal(err)
		}
		ec, err = kuznyechik.NewCipher(kENC)
	}
	if err != nil {
		t.Fatal(err)
	}
	return mc, ec
}

func TestKExp15Vectors(t *testing.T) {
	key := hx(t, kexpKeyHex)
	kMAC := hx(t, kexpMACKeyHex)
	kENC := hx(t, kexpENCKeyHex)

	for _, c := range []struct {
		name             string
		magma            bool
		iv, keymac, kexp string
	}{
		{"магма", true, magmaIVHex, magmaKEYMACHex, magmaKEXPHex},
		{"кузнечик", false, kuzIVHex, kuzKEYMACHex, kuzKEXPHex},
	} {
		t.Run(c.name, func(t *testing.T) {
			iv := hx(t, c.iv)
			wantKEXP := hx(t, c.kexp)
			wantMAC := hx(t, c.keymac)

			macC, encC := newVectorCiphers(t, c.magma, kMAC, kENC)

			// Промежуточное значение KEYMAC приведено в стандарте
			// отдельно: сверяется и оно.
			m, err := gost3413.NewMAC(macC, macC.BlockSize())
			if err != nil {
				t.Fatal(err)
			}
			m.Write(iv)
			m.Write(key)
			if got := m.Sum(nil); !bytes.Equal(got, wantMAC) {
				t.Fatalf("KEYMAC = %X, ожидалось %X", got, wantMAC)
			}

			got, err := KExp15(macC, encC, iv, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wantKEXP) {
				t.Fatalf("KEXP:\n  получено  %X\n  ожидалось %X", got, wantKEXP)
			}

			back, err := KImp15(macC, encC, iv, wantKEXP)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, key) {
				t.Fatalf("KImp15 = %X, ожидалось %X", back, key)
			}
		})
	}
}
