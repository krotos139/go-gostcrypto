// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package mac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// Р 50.1.113-2016, приложение А (RFC 7836, приложение B, примеры 1 и 2).
const (
	testKey  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testData = "0126bdb87800af214341456563780100"

	want256 = "a1aa5f7de402d7b3d323f2991c8d4534" +
		"013137010a83754fd0af6d7cd4922ed9"

	want512 = "a59bab22ecae19c65fbde6e5f4e9f5d8" +
		"549d31f037f9df9b905500e171923a77" +
		"3d5f1530f2ed7e964cb2eedc29e9ad2f" +
		"3afe93b2814f79f5000ffc0366c251e6"
)

func TestKAT(t *testing.T) {
	key, data := mustHex(t, testKey), mustHex(t, testData)

	if got, want := Sum256(key, data), mustHex(t, want256); !bytes.Equal(got, want) {
		t.Errorf("HMAC_256 = %x\n  ожидалось %x", got, want)
	}
	if got, want := Sum512(key, data), mustHex(t, want512); !bytes.Equal(got, want) {
		t.Errorf("HMAC_512 = %x\n  ожидалось %x", got, want)
	}
}

// Размер блока итерационной процедуры равен 64 байтам для обеих длин
// хэш-кода. Если бы у 256-битного варианта он совпадал с длиной выхода,
// значения ipad и opad получились бы другими и KAT не сошёлся бы.
func TestBlockSize(t *testing.T) {
	if got := New256(nil).BlockSize(); got != BlockSize {
		t.Errorf("New256().BlockSize() = %d, ожидалось %d", got, BlockSize)
	}
	if got := New512(nil).BlockSize(); got != BlockSize {
		t.Errorf("New512().BlockSize() = %d, ожидалось %d", got, BlockSize)
	}
	if got := New256(nil).Size(); got != Size256 {
		t.Errorf("New256().Size() = %d", got)
	}
	if got := New512(nil).Size(); got != Size512 {
		t.Errorf("New512().Size() = %d", got)
	}
}

func TestChunkedAndReset(t *testing.T) {
	key, data := mustHex(t, testKey), mustHex(t, testData)
	want := mustHex(t, want256)

	for _, chunk := range []int{1, 3, 7, 16, 64} {
		h := New256(key)
		for off := 0; off < len(data); off += chunk {
			h.Write(data[off:min(off+chunk, len(data))])
		}
		if got := h.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("куски по %d: %x", chunk, got)
		}
	}

	h := New256(key)
	h.Write([]byte("мусор"))
	h.Reset()
	h.Write(data)
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("после Reset: %x", got)
	}
}

// Ключи длиннее блока хэшируются, короче — дополняются нулями; это
// поведение обеспечивает crypto/hmac, здесь проверяется, что оно не
// ломается на "Стрибоге".
func TestKeyLengths(t *testing.T) {
	data := []byte("сообщение")
	seen := make(map[string]bool)
	for _, n := range []int{0, 1, 32, 63, 64, 65, 128} {
		key := make([]byte, n)
		for i := range key {
			key[i] = byte(i + 1)
		}
		sum := string(Sum256(key, data))
		if seen[sum] {
			t.Errorf("ключ длины %d дал уже встречавшуюся имитовставку", n)
		}
		seen[sum] = true
	}
}

func TestEqual(t *testing.T) {
	a := mustHex(t, want256)
	b := append([]byte(nil), a...)
	if !Equal(a, b) {
		t.Error("одинаковые значения признаны разными")
	}
	b[0] ^= 1
	if Equal(a, b) {
		t.Error("разные значения признаны одинаковыми")
	}
}

func BenchmarkSum256(b *testing.B) {
	key := make([]byte, 32)
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(key, buf)
	}
}
