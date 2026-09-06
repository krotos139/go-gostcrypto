// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package acpkm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			return -1
		}
		return r
	}, s)
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("некорректный hex: %v", err)
	}
	return b
}

// Контрольный пример из приложения A.2.2 к RFC 8645. Он приведён для
// AES-256, а не для отечественных шифров: конструкция от шифра не
// зависит, поэтому проверка идёт на AES из стандартной библиотеки.
// Так вектор остаётся тем самым, что напечатан в стандарте, а не
// пересчитанным мной.
const (
	// k = 256, n = 128, c = 64, N = 256 бит, T* = 512 бит.
	masterKeyHex = `88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77
	                FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF`
	// В стандарте напечатано шестнадцать байт, но при c = 64 значащими
	// являются только первые восемь: CTR_1 = ICN || 0^c.
	masterICNHex = `12 34 56 78 90 AB CE F0`

	masterPlainHex = `11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
	                  00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
	                  11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
	                  22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
	                  33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22
	                  44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33
	                  55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 44`

	masterMaterialHex = `9F 10 BB F1 3A 79 FB BD 4A 4C A8 64 C4 90 74 64
	                     39 FE 50 6D 4B 86 9B 21 03 A3 B6 A4 79 28 3C 60
	                     77 91 17 50 E0 D1 77 E5 9A 13 78 2B F1 89 08 D0
	                     AB 6B 59 EE 92 49 05 B3 AB C7 A4 E3 69 65 76 C3
	                     E8 76 2B 30 8B 08 EB CE 3E 93 9A C2 C0 3E 76 D4
	                     60 9A AB D9 15 33 13 D3 CF D3 94 E7 75 DF 3A 94
	                     F2 EE 91 45 6B DC 3D E4 91 2C 87 C3 29 CF 31 A9
	                     2F 20 2E 5A C4 9A 2A 65 31 33 D6 74 8C 4F F9 12`

	// Блоки гаммы G_1..G_5 приведены в стандарте отдельно; шифртекст
	// собирается из них сложением с открытым текстом по модулю 2.
	masterGammaHex = `8C A2 B6 82 A7 50 65 3F 8E BF 08 E7 9F 99 4D 5C
	                  F6 A6 A5 BA 58 14 1E ED 23 DC 31 68 D2 35 89 A1
	                  4A 07 5F 86 05 87 72 94 1D 8E 7D F8 32 F4 23 71
	                  23 35 66 AF 61 DD FE A7 B1 68 3F BA B0 52 4A D7
	                  A8 09 6D BC E8 BB 52 FC DE 6E 03 70 C1 66 95 E8`
)

func TestMasterKeysRFC8645(t *testing.T) {
	key := unhex(t, masterKeyHex)
	want := unhex(t, masterMaterialHex)

	// d = k = 32 байта, l = 4 секции, T* = 64 байта.
	got, err := MasterKeys(aes.NewCipher, key, 64, 32, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ключевой материал:\n  получено %x\n  ожидалось %x", got, want)
	}
}

func TestCTRMasterRFC8645(t *testing.T) {
	key := unhex(t, masterKeyHex)
	icn := unhex(t, masterICNHex)
	plain := unhex(t, masterPlainHex)
	gamma := unhex(t, masterGammaHex)

	// N = 32 байта, T* = 64 байта.
	st, err := NewCTRMaster(aes.NewCipher, key, icn, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	st.XORKeyStream(got, plain)

	// Стандарт печатает первые пять блоков гаммы: сверяем ту часть
	// шифртекста, которая ими покрыта.
	for i := range gamma {
		if want := plain[i] ^ gamma[i]; got[i] != want {
			t.Fatalf("байт %d: %02x, ожидалось %02x", i, got[i], want)
		}
	}

	// Ключи секций обязаны быть теми же, что и в MasterKeys.
	material, err := MasterKeys(aes.NewCipher, key, 64, 32, 4)
	if err != nil {
		t.Fatal(err)
	}
	for section := 0; section < 4; section++ {
		b, err := aes.NewCipher(material[section*32 : (section+1)*32])
		if err != nil {
			t.Fatal(err)
		}
		// Два блока на секцию при N = 32 и n = 16.
		for j := 0; j < 2; j++ {
			blk := section*2 + j
			if (blk+1)*16 > len(gamma) {
				continue
			}
			ctr := make([]byte, 16)
			copy(ctr, icn)
			ctr[15] = byte(blk)
			var g [16]byte
			b.Encrypt(g[:], ctr)
			if !bytes.Equal(g[:], gamma[blk*16:(blk+1)*16]) {
				t.Fatalf("секция %d, блок %d: гамма не совпала", section+1, j+1)
			}
		}
	}
}

// Расшифрование — то же преобразование, что и зашифрование.
func TestCTRMasterRoundTrip(t *testing.T) {
	key := unhex(t, masterKeyHex)
	icn := unhex(t, masterICNHex)

	for _, n := range []int{0, 1, 16, 17, 32, 33, 112, 500} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 7)
		}

		enc, err := NewCTRMaster(aes.NewCipher, key, icn, 32, 64)
		if err != nil {
			t.Fatal(err)
		}
		ct := make([]byte, n)
		enc.XORKeyStream(ct, data)

		dec, err := NewCTRMaster(aes.NewCipher, key, icn, 32, 64)
		if err != nil {
			t.Fatal(err)
		}
		pt := make([]byte, n)
		dec.XORKeyStream(pt, ct)
		if !bytes.Equal(pt, data) {
			t.Fatalf("длина %d: round-trip не сошёлся", n)
		}
	}
}

// Режим должен работать с отечественными шифрами так же, как с любым
// другим: конструкция от шифра не зависит.
func TestCTRMasterWithGOSTCiphers(t *testing.T) {
	for _, c := range []struct {
		name        string
		newCipher   CipherFunc
		blockSize   int
		icnSize     int
		sectionSize int
		masterSize  int
	}{
		{"кузнечик", func(k []byte) (cipher.Block, error) { return kuznyechik.NewCipher(k) }, 16, 8, 32, 64},
		{"магма", func(k []byte) (cipher.Block, error) { return magma.NewCipher(k) }, 8, 4, 16, 32},
	} {
		t.Run(c.name, func(t *testing.T) {
			key := make([]byte, 32)
			for i := range key {
				key[i] = byte(i)
			}
			icn := make([]byte, c.icnSize)
			data := make([]byte, 200)
			for i := range data {
				data[i] = byte(i * 3)
			}

			enc, err := NewCTRMaster(c.newCipher, key, icn, c.sectionSize, c.masterSize)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, len(data))
			enc.XORKeyStream(ct, data)
			if bytes.Equal(ct, data) {
				t.Fatal("шифртекст совпал с открытым текстом")
			}

			dec, err := NewCTRMaster(c.newCipher, key, icn, c.sectionSize, c.masterSize)
			if err != nil {
				t.Fatal(err)
			}
			pt := make([]byte, len(ct))
			dec.XORKeyStream(pt, ct)
			if !bytes.Equal(pt, data) {
				t.Fatal("round-trip не сошёлся")
			}

			// Границы секций обязаны быть заметны: гамма за границей
			// вырабатывается уже другим ключом. Сравниваем с обычным CTR
			// на ключе первой секции.
			material, err := MasterKeys(c.newCipher, key, c.masterSize, len(key), 20)
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.newCipher(material[:len(key)])
			if err != nil {
				t.Fatal(err)
			}
			ctr := make([]byte, c.blockSize)
			copy(ctr, icn)
			plainCTR := cipher.NewCTR(b, ctr)
			ref := make([]byte, len(data))
			plainCTR.XORKeyStream(ref, data)

			if !bytes.Equal(ct[:c.sectionSize], ref[:c.sectionSize]) {
				t.Error("первая секция не совпала с обычным CTR на ключе K^1")
			}
			if bytes.Equal(ct[c.sectionSize:2*c.sectionSize], ref[c.sectionSize:2*c.sectionSize]) {
				t.Error("вторая секция шифруется тем же ключом — смены ключа не произошло")
			}
		})
	}
}

// Ключи секций не выводятся друг из друга: материал берётся из потока,
// поэтому знание K^2 не даёт K^3. Проверяем хотя бы то, что все ключи
// секций различны и не совпадают с исходным.
func TestMasterKeysDistinct(t *testing.T) {
	key := unhex(t, masterKeyHex)
	material, err := MasterKeys(aes.NewCipher, key, 64, 32, 8)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		k := string(material[i*32 : (i+1)*32])
		if seen[k] {
			t.Fatalf("ключ секции %d повторяется", i+1)
		}
		seen[k] = true
		if bytes.Equal([]byte(k), key) {
			t.Fatalf("ключ секции %d совпал с мастер-ключом", i+1)
		}
	}

	// Материал не должен зависеть от того, сколько секций запрошено:
	// первые l ключей одинаковы при любом l.
	short, err := MasterKeys(aes.NewCipher, key, 64, 32, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(short, material[:len(short)]) {
		t.Fatal("материал зависит от числа запрошенных секций")
	}
}

func TestCTRMasterParamValidation(t *testing.T) {
	key := unhex(t, masterKeyHex)
	icn := unhex(t, masterICNHex)

	for _, n := range []int{0, -16, 15, 17, 33} {
		if _, err := NewCTRMaster(aes.NewCipher, key, icn, n, 64); err == nil {
			t.Errorf("размер секции %d принят", n)
		}
	}
	for _, n := range []int{0, -16, 15, 17} {
		if _, err := NewCTRMaster(aes.NewCipher, key, icn, 32, n); err != ErrMasterSectionSize {
			t.Errorf("частота смены мастер-ключа %d: err = %v", n, err)
		}
	}
	for _, n := range []int{0, 1, 13, 16} {
		if _, err := NewCTRMaster(aes.NewCipher, key, make([]byte, n), 32, 64); err != ErrICNSize {
			t.Errorf("|ICN| = %d: err = %v", n, err)
		}
	}
	for _, d := range []int{0, -1} {
		if _, err := MasterKeys(aes.NewCipher, key, 64, d, 4); err != ErrKeySize {
			t.Errorf("d = %d: err = %v", d, err)
		}
	}
	if _, err := MasterKeys(aes.NewCipher, key, 64, 32, 0); err != ErrKeySize {
		t.Error("l = 0 принято")
	}
	if _, err := NewCTRMaster(aes.NewCipher, make([]byte, 7), icn, 32, 64); err == nil {
		t.Error("недопустимая длина ключа принята")
	}
}

func BenchmarkCTRMasterKuznyechik(b *testing.B) {
	key := make([]byte, 32)
	icn := make([]byte, 8)
	buf := make([]byte, 8192)
	st, err := NewCTRMaster(func(k []byte) (cipher.Block, error) { return kuznyechik.NewCipher(k) },
		key, icn, 4096, 8192)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.XORKeyStream(buf, buf)
	}
}
