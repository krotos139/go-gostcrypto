// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package mgm

import (
	"bytes"
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

// Контрольные примеры из RFC 9058, приложение A.
var vectors = []struct {
	name      string
	newCipher func([]byte) (cipher.Block, error)
	key       string
	icn       string
	ad        string
	plain     string
	cipher    string
	tag       string
}{
	{
		name:      "кузнечик, пример 1",
		newCipher: kuznyechik.NewCipher,
		key:       "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
		icn:       "1122334455667700ffeeddccbbaa9988",
		ad: "0202020202020202010101010101010104040404040404040303030303030303" +
			"ea0505050505050505",
		plain: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a" +
			"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011" +
			"aabbcc",
		cipher: "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39" +
			"497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb" +
			"2c7552",
		tag: "cf5d656f40c34f5c46e8bb0e29fcdb4c",
	},
	{
		name:      "кузнечик, пример 2 (пустой открытый текст)",
		newCipher: kuznyechik.NewCipher,
		key:       "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88",
		icn:       "1122334455667700ffeeddccbbaa9988",
		ad:        "01010101010101010101010101010101",
		plain:     "",
		cipher:    "",
		tag:       "7901e9ea2085cd247ed249695f9f8a85",
	},
	{
		name:      "магма, пример 1",
		newCipher: magma.NewCipher,
		key:       "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		icn:       "12def06b3c130a59",
		ad: "0101010101010101020202020202020203030303030303030404040404040404" +
			"0505050505050505ea",
		plain: "ffeeddccbbaa998811223344556677008899aabbcceeff0a0011223344556677" +
			"99aabbcceeff0a001122334455667788aabbcceeff0a00112233445566778899" +
			"aabbcc",
		cipher: "c795066c5f9ea03b85113342459185ae1f2e00d6bf2b785d940470b8bb9c8e7d" +
			"9a5dd3731f7ddc70ec27cb0ace6fa57670f65c646abb75d547aa37c3bcb5c34e" +
			"03bb9c",
		tag: "a7928069aa10fd10",
	},
	{
		name:      "магма, пример 2 (пустые связанные данные)",
		newCipher: magma.NewCipher,
		key:       "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88",
		icn:       "0077665544332211",
		ad:        "",
		plain:     "22334455667700ff",
		cipher:    "6a95e1426b259d4e",
		tag:       "334ee270450bec9e",
	},
}

func TestRFC9058(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			blk, err := v.newCipher(mustHex(t, v.key))
			if err != nil {
				t.Fatal(err)
			}
			tag := mustHex(t, v.tag)
			aead, err := NewMGM(blk, len(tag))
			if err != nil {
				t.Fatal(err)
			}

			icn := mustHex(t, v.icn)
			ad := mustHex(t, v.ad)
			plain := mustHex(t, v.plain)
			want := append(mustHex(t, v.cipher), tag...)

			got := aead.Seal(nil, icn, plain, ad)
			if !bytes.Equal(got, want) {
				t.Fatalf("Seal = %x\n  ожидалось %x", got, want)
			}

			back, err := aead.Open(nil, icn, want, ad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatalf("Open = %x, ожидалось %x", back, plain)
			}
		})
	}
}

// Любое изменение шифртекста, имитовставки, связанных данных или
// синхропосылки должно приводить к отказу.
func TestOpenRejectsTampering(t *testing.T) {
	v := vectors[0]
	blk, err := v.newCipher(mustHex(t, v.key))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := NewMGM(blk, len(mustHex(t, v.tag)))
	if err != nil {
		t.Fatal(err)
	}
	icn := mustHex(t, v.icn)
	ad := mustHex(t, v.ad)
	sealed := append(mustHex(t, v.cipher), mustHex(t, v.tag)...)

	t.Run("шифртекст", func(t *testing.T) {
		for _, pos := range []int{0, 1, len(sealed) / 2, len(sealed) - 17} {
			bad := append([]byte(nil), sealed...)
			bad[pos] ^= 0x01
			if _, err := aead.Open(nil, icn, bad, ad); err != ErrOpen {
				t.Errorf("байт %d: err = %v", pos, err)
			}
		}
	})
	t.Run("имитовставка", func(t *testing.T) {
		for _, pos := range []int{len(sealed) - 16, len(sealed) - 1} {
			bad := append([]byte(nil), sealed...)
			bad[pos] ^= 0x80
			if _, err := aead.Open(nil, icn, bad, ad); err != ErrOpen {
				t.Errorf("байт %d: err = %v", pos, err)
			}
		}
	})
	t.Run("связанные данные", func(t *testing.T) {
		bad := append([]byte(nil), ad...)
		bad[0] ^= 0x01
		if _, err := aead.Open(nil, icn, sealed, bad); err != ErrOpen {
			t.Errorf("err = %v", err)
		}
		if _, err := aead.Open(nil, icn, sealed, ad[:len(ad)-1]); err != ErrOpen {
			t.Errorf("укороченные связанные данные: err = %v", err)
		}
	})
	t.Run("синхропосылка", func(t *testing.T) {
		// Изменённая синхропосылка — обычный отказ аутентификации.
		bad := append([]byte(nil), icn...)
		bad[len(bad)-1] ^= 0x01
		if _, err := aead.Open(nil, bad, sealed, ad); err != ErrOpen {
			t.Errorf("изменённая синхропосылка: err = %v", err)
		}
		// Неверная длина — ошибка вызывающего кода, поэтому паника:
		// так же ведут себя AEAD из стандартной библиотеки.
		func() {
			defer func() {
				if recover() == nil {
					t.Error("синхропосылка неверной длины принята без паники")
				}
			}()
			aead.Open(nil, icn[:len(icn)-1], sealed, ad)
		}()
	})
	t.Run("слишком короткий вход", func(t *testing.T) {
		if _, err := aead.Open(nil, icn, sealed[:3], ad); err != ErrOpen {
			t.Errorf("err = %v", err)
		}
	})
}

// Старший бит синхропосылки отведён под различение потоков и обязан быть
// нулевым.
func TestNonceHighBitRejected(t *testing.T) {
	blk, err := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := NewMGM(blk, 16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	nonce[0] = 0x80

	defer func() {
		if recover() == nil {
			t.Fatal("синхропосылка со старшим единичным битом принята")
		}
	}()
	aead.Seal(nil, nonce, []byte("данные"), nil)
}

func TestRoundTripLengths(t *testing.T) {
	blk, err := magma.NewCipher(make([]byte, magma.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := NewMGM(blk, 8)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	nonce[0] = 0x01

	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i * 7)
	}

	for _, pl := range []int{0, 1, 7, 8, 9, 63, 64, 65, 200} {
		for _, al := range []int{0, 1, 8, 17, 64} {
			if pl == 0 && al == 0 {
				continue // стандарт требует 0 < |A| + |P|
			}
			plain, ad := data[:pl], data[:al]
			sealed := aead.Seal(nil, nonce, plain, ad)
			if len(sealed) != pl+aead.Overhead() {
				t.Fatalf("|P|=%d: длина результата %d", pl, len(sealed))
			}
			back, err := aead.Open(nil, nonce, sealed, ad)
			if err != nil {
				t.Fatalf("|P|=%d |A|=%d: %v", pl, al, err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatalf("|P|=%d |A|=%d: round-trip не сошёлся", pl, al)
			}
		}
	}
}

// Шифрование "на месте": dst использует память plaintext.
func TestSealInPlace(t *testing.T) {
	v := vectors[3]
	blk, err := v.newCipher(mustHex(t, v.key))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := NewMGM(blk, len(mustHex(t, v.tag)))
	if err != nil {
		t.Fatal(err)
	}

	plain := mustHex(t, v.plain)
	buf := make([]byte, 0, len(plain)+aead.Overhead())
	buf = append(buf, plain...)

	got := aead.Seal(buf[:0], mustHex(t, v.icn), buf, mustHex(t, v.ad))
	want := append(mustHex(t, v.cipher), mustHex(t, v.tag)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Seal на месте = %x, ожидалось %x", got, want)
	}
}

func TestParamValidation(t *testing.T) {
	kuz, err := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 0, 3, 17, 64} {
		if _, err := NewMGM(kuz, n); err != ErrTagSize {
			t.Errorf("tagSize = %d: err = %v, ожидалось ErrTagSize", n, err)
		}
	}
	for _, n := range []int{MinTagSize, 8, 16} {
		if _, err := NewMGM(kuz, n); err != nil {
			t.Errorf("tagSize = %d отвергнут: %v", n, err)
		}
	}
}

func BenchmarkSealKuznyechik(b *testing.B) {
	blk, _ := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	aead, _ := NewMGM(blk, 16)
	nonce := make([]byte, aead.NonceSize())
	buf := make([]byte, 8192)
	out := make([]byte, 0, len(buf)+aead.Overhead())
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(out[:0], nonce, buf, nil)
	}
}
