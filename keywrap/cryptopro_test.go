// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"bytes"
	"testing"

	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

// Контрольных примеров для алгоритмов RFC 4357, пп. 6.1-6.5, в самом
// стандарте нет. Правильность подтверждена иначе: сообщение, собранное
// на этих функциях, расшифровывается КриптоПро (см. пакет cms). Здесь
// проверяются свойства, которые обязаны выполняться независимо от
// совместимости.

func kw(t testing.TB) (kek, ukm, cek []byte, sbox *gost28147.SBox) {
	t.Helper()
	kek = make([]byte, gost28147.KeySize)
	cek = make([]byte, gost28147.KeySize)
	for i := range kek {
		kek[i] = byte(i * 3)
		cek[i] = byte(255 - i*5)
	}
	ukm = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	return kek, ukm, cek, gost28147.ParamCryptoProA()
}

func TestCryptoProWrapRoundTrip(t *testing.T) {
	kek, ukm, cek, sbox := kw(t)

	wrapped, err := WrapCryptoPro(kek, ukm, cek, sbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != WrappedSize {
		t.Fatalf("длина завёрнутого ключа %d, ожидалось %d", len(wrapped), WrappedSize)
	}
	if !bytes.Equal(wrapped[:UKMSize], ukm) {
		t.Error("UKM не в начале завёрнутого представления")
	}
	if bytes.Contains(wrapped[UKMSize:], cek) {
		t.Error("исходный ключ виден в завёрнутом представлении")
	}

	back, err := UnwrapCryptoPro(kek, wrapped, sbox)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, cek) {
		t.Fatalf("round-trip не сошёлся: %x вместо %x", back, cek)
	}
}

func TestGOSTWrapRoundTrip(t *testing.T) {
	kek, ukm, cek, sbox := kw(t)

	wrapped, err := WrapGOST(kek, ukm, cek, sbox)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnwrapGOST(kek, wrapped, sbox)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, cek) {
		t.Fatal("round-trip без диверсификации не сошёлся")
	}

	// Два алгоритма обязаны давать разный результат: в этом весь смысл
	// диверсификации.
	cp, err := WrapCryptoPro(kek, ukm, cek, sbox)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped, cp) {
		t.Fatal("диверсификация не повлияла на результат")
	}
	// И перепутать их нельзя.
	if _, err := UnwrapGOST(kek, cp, sbox); err != ErrMAC {
		t.Errorf("разворачивание чужим алгоритмом: err = %v", err)
	}
}

// Диверсификация обязана зависеть от каждого бита UKM: иначе разные
// сообщения шифровались бы одним ключом.
func TestDiversifyDependsOnEveryBit(t *testing.T) {
	kek, ukm, _, sbox := kw(t)

	base, err := DiversifyKEK(kek, ukm, sbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != gost28147.KeySize {
		t.Fatalf("длина ключа %d", len(base))
	}
	if bytes.Equal(base, kek) {
		t.Fatal("диверсифицированный ключ совпал с исходным")
	}

	seen := map[string]bool{string(base): true}
	for i := 0; i < UKMSize; i++ {
		for bit := 0; bit < 8; bit++ {
			other := append([]byte(nil), ukm...)
			other[i] ^= 1 << uint(bit)
			got, err := DiversifyKEK(kek, other, sbox)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatalf("бит %d байта %d UKM не влияет на ключ", bit, i)
			}
			if seen[string(got)] {
				t.Fatalf("бит %d байта %d UKM дал повтор", bit, i)
			}
			seen[string(got)] = true
		}
	}

	// И от каждого байта исходного ключа.
	for i := 0; i < gost28147.KeySize; i++ {
		other := append([]byte(nil), kek...)
		other[i] ^= 0x01
		got, err := DiversifyKEK(other, ukm, sbox)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, base) {
			t.Fatalf("байт %d ключа не влияет на результат", i)
		}
	}
}

func TestCryptoProUnwrapRejectsTampering(t *testing.T) {
	kek, ukm, cek, sbox := kw(t)
	wrapped, err := WrapCryptoPro(kek, ukm, cek, sbox)
	if err != nil {
		t.Fatal(err)
	}

	// Любой изменённый байт обязан ломать проверку.
	for _, pos := range []int{0, UKMSize, UKMSize + 16, WrappedSize - 1} {
		bad := append([]byte(nil), wrapped...)
		bad[pos] ^= 0x01
		if _, err := UnwrapCryptoPro(kek, bad, sbox); err == nil {
			t.Errorf("байт %d: испорченное представление принято", pos)
		}
	}

	// Чужой ключ заворачивания.
	other := append([]byte(nil), kek...)
	other[0] ^= 0x01
	if _, err := UnwrapCryptoPro(other, wrapped, sbox); err != ErrMAC {
		t.Errorf("чужой ключ: err = %v", err)
	}

	// Чужой набор подстановок.
	if _, err := UnwrapCryptoPro(kek, wrapped, gost28147.ParamCryptoProB()); err != ErrMAC {
		t.Error("чужой набор подстановок принят")
	}
}

// Разные UKM на одном ключе обязаны давать разное представление: ради
// этого диверсификация и введена.
func TestCryptoProUKMMatters(t *testing.T) {
	kek, _, cek, sbox := kw(t)

	a, err := WrapCryptoPro(kek, []byte{1, 0, 0, 0, 0, 0, 0, 0}, cek, sbox)
	if err != nil {
		t.Fatal(err)
	}
	b, err := WrapCryptoPro(kek, []byte{2, 0, 0, 0, 0, 0, 0, 0}, cek, sbox)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[UKMSize:], b[UKMSize:]) {
		t.Fatal("разные UKM дали одинаковый результат")
	}
}

func TestCryptoProParamValidation(t *testing.T) {
	kek, ukm, cek, sbox := kw(t)

	for _, n := range []int{0, 7, 9, 16} {
		if _, err := WrapCryptoPro(kek, make([]byte, n), cek, sbox); err != ErrSeedSize {
			t.Errorf("|ukm| = %d: err = %v", n, err)
		}
		if _, err := DiversifyKEK(kek, make([]byte, n), sbox); err != ErrSeedSize {
			t.Errorf("DiversifyKEK, |ukm| = %d: err = %v", n, err)
		}
	}
	for _, n := range []int{0, 8, 16, 31, 33, 64} {
		if _, err := WrapCryptoPro(kek, ukm, make([]byte, n), sbox); err != ErrKeySize {
			t.Errorf("|cek| = %d: err = %v", n, err)
		}
		if _, err := DiversifyKEK(make([]byte, n), ukm, sbox); err != ErrKeySize {
			t.Errorf("DiversifyKEK, |kek| = %d: err = %v", n, err)
		}
	}
	for _, n := range []int{0, 43, 45, 100} {
		if _, err := UnwrapCryptoPro(kek, make([]byte, n), sbox); err != ErrMalformed {
			t.Errorf("|wrapped| = %d: err = %v", n, err)
		}
	}
}

// FuzzCryptoProUnwrap: завёрнутый ключ приходит извне.
func FuzzCryptoProUnwrap(f *testing.F) {
	kek := make([]byte, gost28147.KeySize)
	cek := make([]byte, gost28147.KeySize)
	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	sbox := gost28147.ParamCryptoProA()
	good, err := WrapCryptoPro(kek, ukm, cek, sbox)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte{})
	f.Add(good[:WrappedSize-1])

	f.Fuzz(func(t *testing.T, wrapped []byte) {
		out, err := UnwrapCryptoPro(kek, wrapped, sbox)
		if err != nil {
			return
		}
		// Принятый ключ обязан заворачиваться обратно в тот же вход.
		again, err := WrapCryptoPro(kek, wrapped[:UKMSize], out, sbox)
		if err != nil {
			t.Fatalf("обратное заворачивание: %v", err)
		}
		if !bytes.Equal(again, wrapped) {
			t.Fatal("принят вход, не совпадающий с заворачиванием")
		}
	})
}
