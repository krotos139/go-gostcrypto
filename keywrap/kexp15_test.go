// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
	"github.com/krotos139/go-gostcrypto/gost3413"
)

// RFC 9189 не приводит отдельных контрольных примеров для KExp15:
// значения там вплетены в примеры установления соединения TLS. Поэтому
// проверяется соответствие формуле — имитовставка и гаммирование
// вычисляются здесь отдельно, теми же функциями пакета gost3413, что
// уже сверены с контрольными примерами ГОСТ Р 34.13-2015.

func newCiphers(t testing.TB, useMagma bool) (macC, encC cipher.Block) {
	t.Helper()
	kMAC := make([]byte, 32)
	kENC := make([]byte, 32)
	for i := range kMAC {
		kMAC[i] = byte(i)
		kENC[i] = byte(255 - i)
	}
	var err error
	if useMagma {
		macC, err = magma.NewCipher(kMAC)
		if err != nil {
			t.Fatal(err)
		}
		encC, err = magma.NewCipher(kENC)
	} else {
		macC, err = kuznyechik.NewCipher(kMAC)
		if err != nil {
			t.Fatal(err)
		}
		encC, err = kuznyechik.NewCipher(kENC)
	}
	if err != nil {
		t.Fatal(err)
	}
	return macC, encC
}

func TestKExp15MatchesFormula(t *testing.T) {
	for _, useMagma := range []bool{false, true} {
		macC, encC := newCiphers(t, useMagma)
		n := macC.BlockSize()
		iv := make([]byte, n/2)
		for i := range iv {
			iv[i] = byte(i + 1)
		}

		for _, size := range []int{1, 8, 32, 64, 100} {
			secret := make([]byte, size)
			for i := range secret {
				secret[i] = byte(i * 7)
			}

			got, err := KExp15(macC, encC, iv, secret)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != size+n {
				t.Fatalf("длина %d, ожидалось %d", len(got), size+n)
			}

			// Эталон прямо по формуле: CEK_MAC = OMAC(K_mac, IV ‖ S),
			// затем гаммирование S ‖ CEK_MAC.
			m, err := gost3413.NewMAC(macC, n)
			if err != nil {
				t.Fatal(err)
			}
			m.Write(iv)
			m.Write(secret)
			tag := m.Sum(nil)

			want := append(append([]byte(nil), secret...), tag...)
			st, err := gost3413.NewCTR(encC, iv)
			if err != nil {
				t.Fatal(err)
			}
			st.XORKeyStream(want, want)

			if !bytes.Equal(got, want) {
				t.Fatalf("магма=%v, длина %d:\n  получено  %x\n  по формуле %x",
					useMagma, size, got, want)
			}

			back, err := KImp15(macC, encC, iv, got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, secret) {
				t.Fatal("round-trip не сошёлся")
			}
		}
	}
}

// Имитовставка обязана покрывать и синхропосылку: иначе представление
// можно было бы перенести к другому IV.
func TestKExp15CoversIV(t *testing.T) {
	macC, encC := newCiphers(t, false)
	n := macC.BlockSize()
	secret := bytes.Repeat([]byte{0xAA}, 32)

	ivA := make([]byte, n/2)
	ivB := make([]byte, n/2)
	ivB[0] = 1

	a, err := KExp15(macC, encC, ivA, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := KImp15(macC, encC, ivB, a); err != ErrMAC {
		t.Errorf("представление принято с чужой синхропосылкой: err = %v", err)
	}
}

func TestKImp15RejectsTampering(t *testing.T) {
	macC, encC := newCiphers(t, false)
	n := macC.BlockSize()
	iv := bytes.Repeat([]byte{0x5A}, n/2)
	secret := bytes.Repeat([]byte{0x33}, 32)

	exported, err := KExp15(macC, encC, iv, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, pos := range []int{0, len(exported) / 2, len(exported) - 1} {
		bad := append([]byte(nil), exported...)
		bad[pos] ^= 0x01
		if _, err := KImp15(macC, encC, iv, bad); err != ErrMAC {
			t.Errorf("байт %d: err = %v", pos, err)
		}
	}

	// Чужие ключи.
	otherMAC, otherENC := newCiphers(t, true)
	if _, err := KImp15(otherMAC, otherENC, iv[:otherMAC.BlockSize()/2], exported); err == nil {
		t.Error("чужие ключи приняты")
	}
}

// Секрет не должен быть виден в экспортированном представлении.
func TestKExp15HidesSecret(t *testing.T) {
	macC, encC := newCiphers(t, false)
	iv := make([]byte, macC.BlockSize()/2)
	secret := []byte("совершенно секретный ключ 32 бай")

	exported, err := KExp15(macC, encC, iv, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(exported, secret) {
		t.Fatal("секрет виден в экспортированном представлении")
	}
}

func TestKExp15ParamValidation(t *testing.T) {
	macC, encC := newCiphers(t, false)
	n := macC.BlockSize()
	iv := make([]byte, n/2)

	for _, bad := range []int{0, 1, n/2 - 1, n/2 + 1, n} {
		if _, err := KExp15(macC, encC, make([]byte, bad), []byte("x")); err != ErrIVSize {
			t.Errorf("|iv| = %d: err = %v", bad, err)
		}
	}
	if _, err := KExp15(macC, encC, iv, nil); err != ErrKeySize {
		t.Error("пустой секрет принят")
	}

	// Разный размер блока у шифров.
	magmaC, _ := newCiphers(t, true)
	if _, err := KExp15(magmaC, encC, make([]byte, 4), []byte("x")); err != ErrBlockMismatch {
		t.Error("шифры с разным блоком приняты")
	}

	// Представление короче имитовставки.
	for _, size := range []int{0, 1, n} {
		if _, err := KImp15(macC, encC, iv, make([]byte, size)); err != ErrExportedSize {
			t.Errorf("|exported| = %d: err = %v", size, err)
		}
	}
}

// FuzzKImp15: представление приходит извне.
func FuzzKImp15(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 8))

	f.Fuzz(func(t *testing.T, exported, ivSeed []byte) {
		macC, encC := newCiphers(t, false)
		n := macC.BlockSize()
		iv := make([]byte, n/2)
		copy(iv, ivSeed)

		secret, err := KImp15(macC, encC, iv, exported)
		if err != nil {
			return
		}
		// Принятое представление обязано собираться обратно точь-в-точь.
		again, err := KExp15(macC, encC, iv, secret)
		if err != nil {
			t.Fatalf("обратный экспорт: %v", err)
		}
		if !bytes.Equal(again, exported) {
			t.Fatal("принято представление, не совпадающее с экспортом")
		}
	})
}
