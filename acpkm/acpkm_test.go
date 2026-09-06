// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package acpkm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// Контрольные примеры RFC 8645 построены на AES-256, а не на
// отечественных шифрах: сам режим от шифра не зависит и работает с любым
// cipher.Block. Проверка на AES подтверждает логику перевыработки ключа и
// счётчика; работоспособность с "Магмой" и "Кузнечиком" проверяется
// отдельно на round-trip.
//
// Контрольные примеры для CTR-ACPKM на отечественных шифрах есть только в
// Р 1323565.1.017-2018, который в открытом доступе недоступен, поэтому в
// тестах их нет.

const (
	rfcKey = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
	rfcICN = "1234567890abcef0"

	rfcPlain = "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a" +
		"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011" +
		"33445566778899aabbcceeff0a001122445566778899aabbcceeff0a00112233" +
		"5566778899aabbcceeff0a0011223344"

	rfcCipher = "ec5ccbde8c18d3b8725668d0a737f4581989e74232629d60997de24bc0e39fb8" +
		"f5aaba0be364f053eef0bc15c2764cea9e7cc376bd8719c9770fca2de2a37cb5" +
		"5b2b771bf83a0517be042d8228fe2a95844e9f08fdf7b8944cb7aab7de3c67b4" +
		"56b843fc3231de46d5ab14f8ac09c739"
)

// Ключи секций из того же примера: они позволяют проверить само
// преобразование ACPKM, а не только итоговый шифртекст.
var sectionKeys = []string{
	"8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
	"f680d1212fa43df4ec3a91de2ab16f1b36b0488a4fc12e0998d2e4a888e84f3d",
	"8eb97e43271a42f1ca8ee25f5cc7c83b1ace9e5ed06aa53b57b96acf365d24b8",
	"c5716cc96798bc2d4a1787b78adf94ace816f80bdbbcad7d6078129c0cb402f5",
}

func TestACPKMDerive(t *testing.T) {
	for i := 0; i+1 < len(sectionKeys); i++ {
		b, err := aes.NewCipher(mustHex(t, sectionKeys[i]))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Derive(b, 32)
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex(t, sectionKeys[i+1]); !bytes.Equal(got, want) {
			t.Errorf("K^%d = %x\n  ожидалось %x", i+2, got, want)
		}
	}
}

// Константа D — байты от 0x80 до 0xff; у каждого старший бит единичный.
func TestConstD(t *testing.T) {
	if len(constD) != 128 {
		t.Fatalf("длина D = %d, ожидалось 128", len(constD))
	}
	for i, v := range constD {
		if v != byte(0x80+i) {
			t.Fatalf("D[%d] = %02x, ожидалось %02x", i, v, 0x80+i)
		}
		if v&0x80 == 0 {
			t.Fatalf("D[%d]: старший бит нулевой", i)
		}
	}
}

func TestCTRACPKM(t *testing.T) {
	newAES := func(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }

	plain := mustHex(t, rfcPlain)
	want := mustHex(t, rfcCipher)
	if len(plain) != 112 || len(want) != 112 {
		t.Fatalf("длины примера: |P| = %d, |C| = %d", len(plain), len(want))
	}

	s, err := NewCTR(newAES, mustHex(t, rfcKey), mustHex(t, rfcICN), 32) // N = 256 бит
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	s.XORKeyStream(got, plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("шифрование = %x\n  ожидалось %x", got, want)
	}

	// Расшифрование — то же наложение гаммы.
	s, err = NewCTR(newAES, mustHex(t, rfcKey), mustHex(t, rfcICN), 32)
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(want))
	s.XORKeyStream(back, want)
	if !bytes.Equal(back, plain) {
		t.Fatalf("расшифрование = %x, ожидалось %x", back, plain)
	}
}

// Результат не должен зависеть от нарезки данных между вызовами, включая
// куски, пересекающие границу секции.
func TestCTRACPKMChunked(t *testing.T) {
	newAES := func(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
	plain := mustHex(t, rfcPlain)
	want := mustHex(t, rfcCipher)

	for _, chunk := range []int{1, 3, 15, 16, 17, 31, 32, 33, 112} {
		s, err := NewCTR(newAES, mustHex(t, rfcKey), mustHex(t, rfcICN), 32)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(plain))
		for off := 0; off < len(plain); off += chunk {
			end := min(off+chunk, len(plain))
			s.XORKeyStream(got[off:end], plain[off:end])
		}
		if !bytes.Equal(got, want) {
			t.Errorf("куски по %d: %x", chunk, got)
		}
	}
}

// При размере секции не меньше длины сообщения перевыработки не
// происходит, и режим обязан совпасть с обычным CTR из crypto/cipher.
func TestSingleSectionMatchesPlainCTR(t *testing.T) {
	newAES := func(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
	key := mustHex(t, rfcKey)
	icn := mustHex(t, rfcICN)
	plain := mustHex(t, rfcPlain)

	s, err := NewCTR(newAES, key, icn, 16*len(plain))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	s.XORKeyStream(got, plain)

	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, b.BlockSize())
	copy(iv, icn)
	want := make([]byte, len(plain))
	cipher.NewCTR(b, iv).XORKeyStream(want, plain)

	if !bytes.Equal(got, want) {
		t.Fatalf("одна секция: %x\n  обычный CTR: %x", got, want)
	}
}

// Режим должен работать с отечественными шифрами; официальных векторов
// для них нет, поэтому проверяется round-trip и то, что перевыработка
// действительно происходит.
func TestGOSTCiphers(t *testing.T) {
	cases := []struct {
		name    string
		newCiph CipherFunc
		keySize int
		icnSize int
		section int
	}{
		{"кузнечик", kuznyechik.NewCipher, kuznyechik.KeySize, 8, 32},
		{"магма", magma.NewCipher, magma.KeySize, 4, 16},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := make([]byte, c.keySize)
			for i := range key {
				key[i] = byte(i)
			}
			icn := make([]byte, c.icnSize)
			plain := make([]byte, 200)
			for i := range plain {
				plain[i] = byte(i * 3)
			}

			enc, err := NewCTR(c.newCiph, key, icn, c.section)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, len(plain))
			enc.XORKeyStream(ct, plain)

			dec, err := NewCTR(c.newCiph, key, icn, c.section)
			if err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(ct))
			dec.XORKeyStream(back, ct)
			if !bytes.Equal(back, plain) {
				t.Fatal("round-trip не сошёлся")
			}

			// Перевыработка должна давать иной результат, чем её отсутствие.
			single, err := NewCTR(c.newCiph, key, icn, 16*len(plain))
			if err != nil {
				t.Fatal(err)
			}
			noRekey := make([]byte, len(plain))
			single.XORKeyStream(noRekey, plain)
			if bytes.Equal(ct[:c.section], noRekey[:c.section]) &&
				bytes.Equal(ct, noRekey) {
				t.Fatal("перевыработка ключа не повлияла на результат")
			}
		})
	}
}

func TestParamValidation(t *testing.T) {
	newAES := func(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
	key := mustHex(t, rfcKey)

	for _, n := range []int{0, -16, 15, 17, 31} {
		if _, err := NewCTR(newAES, key, mustHex(t, rfcICN), n); err != ErrSectionSize {
			t.Errorf("размер секции %d: err = %v", n, err)
		}
	}
	// c = 16 - len(icn) байт; допустимо 4 <= c <= 12.
	for _, n := range []int{0, 3, 13, 16, 20} {
		if _, err := NewCTR(newAES, key, make([]byte, n), 32); err != ErrICNSize {
			t.Errorf("|ICN| = %d: err = %v", n, err)
		}
	}
	for _, n := range []int{4, 8, 12} {
		if _, err := NewCTR(newAES, key, make([]byte, n), 32); err != nil {
			t.Errorf("|ICN| = %d отвергнут: %v", n, err)
		}
	}
}

func BenchmarkCTRACPKMKuznyechik(b *testing.B) {
	key := make([]byte, kuznyechik.KeySize)
	icn := make([]byte, 8)
	buf := make([]byte, 8192)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := NewCTR(kuznyechik.NewCipher, key, icn, 4096)
		if err != nil {
			b.Fatal(err)
		}
		s.XORKeyStream(buf, buf)
	}
}
