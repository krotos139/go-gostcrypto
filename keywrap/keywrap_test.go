// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/krotos139/go-gostcrypto/kdf"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// Р 50.1.113-2016, приложение А (RFC 7836, приложение B, пример 11).
const (
	exportKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	keyHex       = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	seedHex      = "af21434145656378"

	kekHex = "a1aa5f7de402d7b3d323f2991c8d4534" +
		"013137010a83754fd0af6d7cd4922ed9"
	macHex = "be33f052"
	encHex = "d15547f8ee85121bc87d4b1027d26027" +
		"ecc071bba6e72f3fec6f620f56834c5a"
)

func TestRFC7836(t *testing.T) {
	exportKey := mustHex(t, exportKeyHex)
	key := mustHex(t, keyHex)
	seed := mustHex(t, seedHex)

	// Промежуточный ключ шифрования ключа приведён в примере отдельно.
	if got, want := kdf.Derive(exportKey, label, seed), mustHex(t, kekHex); !bytes.Equal(got, want) {
		t.Fatalf("KEK = %x\n  ожидалось %x", got, want)
	}

	got, err := Wrap(exportKey, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte(nil), seed...), mustHex(t, encHex)...), mustHex(t, macHex)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Wrap = %x\n  ожидалось %x", got, want)
	}

	back, err := Unwrap(exportKey, got, len(seed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, key) {
		t.Fatalf("Unwrap = %x, ожидалось %x", back, key)
	}
}

// Имитовставка ГОСТ 28147-89 проверяется тем же примером: её значение
// приведено в стандарте отдельно от завёрнутого представления.
func TestMACFromRFC7836(t *testing.T) {
	kek := mustHex(t, kekHex)
	key := mustHex(t, keyHex)
	seed := mustHex(t, seedHex)

	got, err := gost28147.MAC(kek, gost28147.ParamZ(), seed, key, MACSize)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, macHex); !bytes.Equal(got, want) {
		t.Fatalf("имитовставка = %x, ожидалось %x", got, want)
	}
}

func TestUnwrapRejectsTampering(t *testing.T) {
	exportKey := mustHex(t, exportKeyHex)
	key := mustHex(t, keyHex)
	seed := mustHex(t, seedHex)

	wrapped, err := Wrap(exportKey, seed, key)
	if err != nil {
		t.Fatal(err)
	}

	// Порча любого байта должна ломать проверку.
	for _, pos := range []int{0, len(seed), len(wrapped) / 2, len(wrapped) - 1} {
		bad := append([]byte(nil), wrapped...)
		bad[pos] ^= 0x01
		if _, err := Unwrap(exportKey, bad, len(seed)); err == nil {
			t.Errorf("байт %d: испорченное представление принято", pos)
		}
	}

	// Другой ключ экспорта тоже.
	other := append([]byte(nil), exportKey...)
	other[0] ^= 0x01
	if _, err := Unwrap(other, wrapped, len(seed)); err != ErrMAC {
		t.Errorf("чужой ключ экспорта: err = %v", err)
	}
}

func TestRoundTripLengths(t *testing.T) {
	exportKey := mustHex(t, exportKeyHex)
	// Заворачиваются ключи 28147-89 (32 байта) и ключи подписи
	// ГОСТ Р 34.10-2012 (32 или 64 байта).
	for _, keyLen := range []int{8, 32, 64} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i * 3)
		}
		for seedLen := MinSeedSize; seedLen <= MaxSeedSize; seedLen++ {
			seed := make([]byte, seedLen)
			for i := range seed {
				seed[i] = byte(i + 1)
			}
			wrapped, err := Wrap(exportKey, seed, key)
			if err != nil {
				t.Fatalf("|K|=%d |seed|=%d: %v", keyLen, seedLen, err)
			}
			if len(wrapped) != seedLen+keyLen+MACSize {
				t.Fatalf("|K|=%d |seed|=%d: длина %d", keyLen, seedLen, len(wrapped))
			}
			back, err := Unwrap(exportKey, wrapped, seedLen)
			if err != nil {
				t.Fatalf("|K|=%d |seed|=%d: %v", keyLen, seedLen, err)
			}
			if !bytes.Equal(back, key) {
				t.Fatalf("|K|=%d |seed|=%d: round-trip не сошёлся", keyLen, seedLen)
			}
		}
	}
}

// Разные seed на одном ключе экспорта обязаны давать разный результат:
// иначе seed не выполняет свою роль.
func TestSeedMatters(t *testing.T) {
	exportKey := mustHex(t, exportKeyHex)
	key := mustHex(t, keyHex)

	a, err := Wrap(exportKey, mustHex(t, "0000000000000001"), key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Wrap(exportKey, mustHex(t, "0000000000000002"), key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[8:], b[8:]) {
		t.Fatal("разные seed дали одинаковое завёрнутое представление")
	}
}

func TestParamValidation(t *testing.T) {
	exportKey := mustHex(t, exportKeyHex)
	key := mustHex(t, keyHex)

	for _, n := range []int{0, 1, 7, 17, 32} {
		if _, err := Wrap(exportKey, make([]byte, n), key); err != ErrSeedSize {
			t.Errorf("|seed| = %d: err = %v", n, err)
		}
	}
	for _, n := range []int{0, 1, 7, 9, 31} {
		if _, err := Wrap(exportKey, make([]byte, 8), make([]byte, n)); err != ErrKeySize {
			t.Errorf("|K| = %d: err = %v", n, err)
		}
	}
	if _, err := Unwrap(exportKey, make([]byte, 10), 8); err != ErrMalformed {
		t.Errorf("короткое представление: err = %v", err)
	}
	if _, err := Unwrap(exportKey, make([]byte, 100), 3); err != ErrSeedSize {
		t.Errorf("недопустимый seedSize: err = %v", err)
	}
}
