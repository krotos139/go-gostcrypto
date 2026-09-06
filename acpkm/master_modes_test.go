// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package acpkm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
)

// Контрольные примеры из приложения A.2.2 к RFC 8645. Как и для CTR, они
// приведены для AES-256: конструкция от шифра не зависит, поэтому проверка
// идёт на AES из стандартной библиотеки, а значения остаются ровно теми,
// что напечатаны в стандарте.

const masterIVHex = `12 34 56 78 90 AB CE F0 A1 B2 C3 D4 E5 F0 01 12`

// п. 6.3.4: N = 256 бит, T* = 512 бит.
const cbcMasterCipherHex = `59 CB 5B CA C2 69 2C 60 0D 46 03 A0 C7 40 C9 7C
                            80 B6 02 74 54 8B F7 C9 78 1F A1 05 8B F6 8B 42
                            8C 24 FB CF 68 15 B1 AF 65 FE 47 75 95 B4 97 59
                            19 65 A5 00 58 0D 50 23 72 1B E9 90 E1 83 30 E9
                            56 D8 34 F4 6F 0F 4D E6 20 53 A9 5C B5 F6 3C 14
                            66 68 2B 8B DD 6E B2 7E DE C7 51 D6 2F 45 A5 45
                            7F 4D 87 F9 CA E9 56 09 79 C4 FA FE 34 0B 45 34`

// п. 6.3.5: тот же ключ и синхропосылка, открытый текст на 8 байт короче.
const (
	cfbMasterPlainHex = `11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
	                     00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
	                     11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
	                     22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
	                     33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22
	                     44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33
	                     55 66 77 88 99 AA BB CC`
	cfbMasterCipherHex = `0D 1B AE 1D AD 3B E6 91 56 3C CF 53 D8 BF 09 8B
	                      6B B3 E7 71 16 3C A0 7C 9D 8D AC 3C 5C A8 09 24
	                      84 67 6C 9F 96 F8 7D 9B 06 61 AB 39 53 86 A9 88
	                      C2 99 76 08 E6 D3 CF 0C 10 F9 73 8D 07 40 C8 A3
	                      CD 06 D9 16 B5 D9 57 B9 8D 0D 51 BB F2 49 77 AB
	                      45 71 E6 F0 0E 81 0F F8 DD E4 33 BF 0A F4 20 90
	                      C2 3A E1 BF CC B4 37 B3`
)

// п. 6.3.6: N = 256 бит, T* = 768 бит, сообщение из пяти полных блоков.
const (
	omacMasterPlainHex = `11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
	                      00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
	                      11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
	                      22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
	                      33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22`
	omacMasterTagHex = `B3 AD B8 92 18 32 05 4C 09 21 E7 B8 08 CF A0 B8`
	// Ключевой материал: на секцию приходится k+n бит, то есть 48 байт.
	omacMasterMaterialHex = `9F 10 BB F1 3A 79 FB BD 4A 4C A8 64 C4 90 74 64
	                         39 FE 50 6D 4B 86 9B 21 03 A3 B6 A4 79 28 3C 60
	                         77 91 17 50 E0 D1 77 E5 9A 13 78 2B F1 89 08 D0
	                         AB 6B 59 EE 92 49 05 B3 AB C7 A4 E3 69 65 76 C3
	                         9D CC 66 42 0D FF 45 5B 21 F3 93 F0 D4 D6 6E 67
	                         BB 1B 06 0B 87 66 6D 08 7A 9D A7 49 55 C3 5B 48
	                         F2 EE 91 45 6B DC 3D E4 91 2C 87 C3 29 CF 31 A9
	                         2F 20 2E 5A C4 9A 2A 65 31 33 D6 74 8C 4F F9 12
	                         78 21 C7 C7 6C BD 79 63 56 AC F8 8E 69 6A 00 07`
)

func TestCBCMasterRFC8645(t *testing.T) {
	key := unhex(t, masterKeyHex)
	iv := unhex(t, masterIVHex)
	plain := unhex(t, masterPlainHex)
	want := unhex(t, cbcMasterCipherHex)

	enc, err := NewCBCMasterEncrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	enc.CryptBlocks(got, plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("шифртекст:\n  получено  %x\n  ожидалось %x", got, want)
	}

	dec, err := NewCBCMasterDecrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(want))
	dec.CryptBlocks(back, want)
	if !bytes.Equal(back, plain) {
		t.Fatalf("расшифрование:\n  получено  %x\n  ожидалось %x", back, plain)
	}
}

func TestCFBMasterRFC8645(t *testing.T) {
	key := unhex(t, masterKeyHex)
	iv := unhex(t, masterIVHex)
	plain := unhex(t, cfbMasterPlainHex)
	want := unhex(t, cfbMasterCipherHex)

	enc, err := NewCFBMasterEncrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	enc.XORKeyStream(got, plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("шифртекст:\n  получено  %x\n  ожидалось %x", got, want)
	}

	dec, err := NewCFBMasterDecrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(want))
	dec.XORKeyStream(back, want)
	if !bytes.Equal(back, plain) {
		t.Fatalf("расшифрование:\n  получено  %x\n  ожидалось %x", back, plain)
	}
}

func TestOMACMasterRFC8645(t *testing.T) {
	key := unhex(t, masterKeyHex)
	data := unhex(t, omacMasterPlainHex)
	want := unhex(t, omacMasterTagHex)

	// Ключевой материал приведён в стандарте отдельно: на секцию идёт
	// k+n = 48 байт, T* = 96 байт.
	material, err := MasterKeys(aes.NewCipher, key, 96, 48, 3)
	if err != nil {
		t.Fatal(err)
	}
	if w := unhex(t, omacMasterMaterialHex); !bytes.Equal(material, w) {
		t.Fatalf("ключевой материал:\n  получено  %x\n  ожидалось %x", material, w)
	}

	got, err := OMACMaster(aes.NewCipher, key, data, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("имитовставка:\n  получено  %x\n  ожидалось %x", got, want)
	}
}

// Sum не должна менять состояние: повторный вызов обязан дать то же
// значение, а дозапись — продолжить с того же места.
func TestOMACMasterSumIsRepeatable(t *testing.T) {
	key := unhex(t, masterKeyHex)
	data := unhex(t, omacMasterPlainHex)

	m, err := NewOMACMaster(aes.NewCipher, key, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	m.Write(data[:32])
	a := m.Sum(nil)
	b := m.Sum(nil)
	if !bytes.Equal(a, b) {
		t.Fatalf("повторный Sum дал другое значение:\n  %x\n  %x", a, b)
	}

	m.Write(data[32:])
	whole, err := OMACMaster(aes.NewCipher, key, data, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Sum(nil); !bytes.Equal(got, whole) {
		t.Fatalf("после дозаписи:\n  получено  %x\n  ожидалось %x", got, whole)
	}
}

func TestOMACMasterReset(t *testing.T) {
	key := unhex(t, masterKeyHex)
	data := unhex(t, omacMasterPlainHex)
	want := unhex(t, omacMasterTagHex)

	m, err := NewOMACMaster(aes.NewCipher, key, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	m.Write(data)
	if got := m.Sum(nil); !bytes.Equal(got, want) {
		t.Fatal("первый проход не сошёлся")
	}
	m.Reset()
	m.Write(data)
	if got := m.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("после Reset:\n  получено  %x\n  ожидалось %x", got, want)
	}
}

// Результат не должен зависеть от нарезки данных между вызовами.
func TestMasterModesChunked(t *testing.T) {
	key := unhex(t, masterKeyHex)
	iv := unhex(t, masterIVHex)
	data := unhex(t, cfbMasterPlainHex)

	cfbWhole := make([]byte, len(data))
	enc, err := NewCFBMasterEncrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	enc.XORKeyStream(cfbWhole, data)

	omacWhole, err := OMACMaster(aes.NewCipher, key, data, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}

	for _, chunk := range []int{1, 3, 16, 17, 32} {
		enc, err := NewCFBMasterEncrypter(aes.NewCipher, key, iv, 32, 64)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(data))
		m, err := NewOMACMaster(aes.NewCipher, key, 32, 96, 16)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(data); i += chunk {
			end := i + chunk
			if end > len(data) {
				end = len(data)
			}
			enc.XORKeyStream(got[i:end], data[i:end])
			m.Write(data[i:end])
		}
		if !bytes.Equal(got, cfbWhole) {
			t.Errorf("CFB, куски по %d байт: результат другой", chunk)
		}
		if !bytes.Equal(m.Sum(nil), omacWhole) {
			t.Errorf("OMAC, куски по %d байт: результат другой", chunk)
		}
	}
}

// Смена ключа на границе секции обязана быть заметна: сравниваем с теми
// же режимами на постоянном ключе K^1.
func TestMasterModesRekeyingHappens(t *testing.T) {
	key := unhex(t, masterKeyHex)
	iv := unhex(t, masterIVHex)
	plain := unhex(t, masterPlainHex)

	material, err := MasterKeys(aes.NewCipher, key, 64, 32, 4)
	if err != nil {
		t.Fatal(err)
	}
	first, err := aes.NewCipher(material[:32])
	if err != nil {
		t.Fatal(err)
	}

	// CBC на постоянном ключе K^1.
	ref := make([]byte, len(plain))
	cipher.NewCBCEncrypter(first, iv).CryptBlocks(ref, plain)

	enc, err := NewCBCMasterEncrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	enc.CryptBlocks(got, plain)

	// Первая секция — два блока при N = 32 и n = 16.
	if !bytes.Equal(got[:32], ref[:32]) {
		t.Error("первая секция не совпала с обычным CBC на ключе K^1")
	}
	if bytes.Equal(got[32:64], ref[32:64]) {
		t.Error("вторая секция шифруется тем же ключом — смены не произошло")
	}
}

// Режимы обязаны работать с отечественными шифрами так же, как с любым
// другим блочным шифром подходящего размера.
func TestMasterModesWithGOSTCiphers(t *testing.T) {
	for _, c := range []struct {
		name        string
		newCipher   CipherFunc
		bs          int
		sectionSize int
		masterSize  int
	}{
		{"кузнечик", func(k []byte) (cipher.Block, error) { return kuznyechik.NewCipher(k) }, 16, 32, 64},
		{"магма", func(k []byte) (cipher.Block, error) { return magma.NewCipher(k) }, 8, 16, 32},
	} {
		t.Run(c.name, func(t *testing.T) {
			key := make([]byte, 32)
			for i := range key {
				key[i] = byte(i * 5)
			}
			iv := make([]byte, c.bs)
			data := make([]byte, 20*c.bs)
			for i := range data {
				data[i] = byte(i * 3)
			}

			enc, err := NewCBCMasterEncrypter(c.newCipher, key, iv, c.sectionSize, c.masterSize)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, len(data))
			enc.CryptBlocks(ct, data)
			dec, err := NewCBCMasterDecrypter(c.newCipher, key, iv, c.sectionSize, c.masterSize)
			if err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(ct))
			dec.CryptBlocks(back, ct)
			if !bytes.Equal(back, data) {
				t.Error("CBC: round-trip не сошёлся")
			}

			// Неполный хвост — только для режима с обратной связью.
			tail := append(append([]byte(nil), data...), 1, 2, 3)
			fe, err := NewCFBMasterEncrypter(c.newCipher, key, iv, c.sectionSize, c.masterSize)
			if err != nil {
				t.Fatal(err)
			}
			fct := make([]byte, len(tail))
			fe.XORKeyStream(fct, tail)
			fd, err := NewCFBMasterDecrypter(c.newCipher, key, iv, c.sectionSize, c.masterSize)
			if err != nil {
				t.Fatal(err)
			}
			fback := make([]byte, len(fct))
			fd.XORKeyStream(fback, fct)
			if !bytes.Equal(fback, tail) {
				t.Error("CFB: round-trip не сошёлся")
			}

			// Имитовставка зависит от каждого байта.
			base, err := OMACMaster(c.newCipher, key, data, c.sectionSize, c.masterSize, c.bs)
			if err != nil {
				t.Fatal(err)
			}
			bad := append([]byte(nil), data...)
			bad[len(bad)-1] ^= 0x01
			other, err := OMACMaster(c.newCipher, key, bad, c.sectionSize, c.masterSize, c.bs)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(base, other) {
				t.Error("OMAC: изменение последнего байта не повлияло")
			}
		})
	}
}

// Полный и неполный последний блок обрабатываются по-разному: во втором
// случае добавочный ключ сдвигается. Значения обязаны различаться даже
// тогда, когда неполное сообщение — префикс полного.
func TestOMACMasterPaddingDistinguishes(t *testing.T) {
	key := unhex(t, masterKeyHex)
	full := make([]byte, 32)
	for i := range full {
		full[i] = byte(i)
	}

	a, err := OMACMaster(aes.NewCipher, key, full, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	// То же сообщение без последнего байта, дополненное так, как это
	// сделал бы режим: если бы сдвига ключа не было, значения совпали бы.
	short := append([]byte(nil), full[:31]...)
	b, err := OMACMaster(aes.NewCipher, key, short, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("полный и неполный последний блок дали одно значение")
	}

	padded := append(append([]byte(nil), full[:31]...), 0x80)
	c, err := OMACMaster(aes.NewCipher, key, padded, 32, 96, 16)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b, c) {
		t.Fatal("дополнение не отличается от явно дописанного байта")
	}
}

func TestMasterModesParamValidation(t *testing.T) {
	key := unhex(t, masterKeyHex)
	iv := unhex(t, masterIVHex)

	for _, n := range []int{0, 1, 15, 17, 32} {
		if _, err := NewCBCMasterEncrypter(aes.NewCipher, key, make([]byte, n), 32, 64); err != ErrIVSize {
			t.Errorf("CBC, |iv| = %d: err = %v", n, err)
		}
		if _, err := NewCFBMasterEncrypter(aes.NewCipher, key, make([]byte, n), 32, 64); err != ErrIVSize {
			t.Errorf("CFB, |iv| = %d: err = %v", n, err)
		}
	}
	for _, n := range []int{0, 15, 17, 33} {
		if _, err := NewCBCMasterEncrypter(aes.NewCipher, key, iv, n, 64); err != ErrSectionSize {
			t.Errorf("размер секции %d: err = %v", n, err)
		}
	}
	for _, n := range []int{0, -1, 17, 33} {
		if _, err := NewOMACMaster(aes.NewCipher, key, 32, 96, n); err != ErrTagSize {
			t.Errorf("длина имитовставки %d: err = %v", n, err)
		}
	}

	// Данные некратной длины в режиме с зацеплением - ошибка вызывающего.
	enc, err := NewCBCMasterEncrypter(aes.NewCipher, key, iv, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("некратная длина данных принята")
			}
		}()
		out := make([]byte, 17)
		enc.CryptBlocks(out, make([]byte, 17))
	}()
}
