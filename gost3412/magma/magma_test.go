// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package magma

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
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

// t восстанавливается из g: g[0](a) = t(a) <<< 11.
func transformT(a uint32) uint32 {
	return bits.RotateLeft32(g(a, 0), -11)
}

// ГОСТ Р 34.12-2015, приложение А.2.1 (RFC 8891, A.1).
func TestTransformT(t *testing.T) {
	cases := []struct{ in, want uint32 }{
		{0xfdb97531, 0x2a196f34},
		{0x2a196f34, 0xebd9f03a},
		{0xebd9f03a, 0xb039bb3d},
		{0xb039bb3d, 0x68695433},
	}
	for _, c := range cases {
		if got := transformT(c.in); got != c.want {
			t.Errorf("t(%08x) = %08x, ожидалось %08x", c.in, got, c.want)
		}
	}
}

// ГОСТ Р 34.12-2015, приложение А.2.2 (RFC 8891, A.2).
func TestTransformG(t *testing.T) {
	cases := []struct{ k, a, want uint32 }{
		{0x87654321, 0xfedcba98, 0xfdcbc20c},
		{0xfdcbc20c, 0x87654321, 0x7e791a4b},
		{0x7e791a4b, 0xfdcbc20c, 0xc76549ec},
		{0xc76549ec, 0x7e791a4b, 0x9791c849},
	}
	for _, c := range cases {
		if got := g(c.a, c.k); got != c.want {
			t.Errorf("g[%08x](%08x) = %08x, ожидалось %08x", c.k, c.a, got, c.want)
		}
	}
}

const testKey = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

// ГОСТ Р 34.12-2015, приложение А.2.3 (RFC 8891, A.3).
func TestKeySchedule(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{
		0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
		0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
		0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
		0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
		0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
		0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
		0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
		0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
	}
	got := blk.(*magmaCipher).rk
	for i, w := range want {
		if got[i] != w {
			t.Errorf("K_%d = %08x, ожидалось %08x", i+1, got[i], w)
		}
	}
}

// ГОСТ Р 34.12-2015, приложение А.2.4 и А.2.5 (RFC 8891, A.4 и A.5).
func TestCipherKAT(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	plain := mustHex(t, "fedcba9876543210")
	cipher := mustHex(t, "4ee901e5c2d8ca3d")

	got := make([]byte, BlockSize)
	blk.Encrypt(got, plain)
	if !bytes.Equal(got, cipher) {
		t.Errorf("Encrypt = %x, ожидалось %x", got, cipher)
	}

	blk.Decrypt(got, cipher)
	if !bytes.Equal(got, plain) {
		t.Errorf("Decrypt = %x, ожидалось %x", got, plain)
	}
}

// Пошаговая сверка раундов: ГОСТ Р 34.12-2015, приложение А.2.4.
// Каждая запись — пара (a_1, a_0) после раунда i.
func TestEncryptRounds(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	c := blk.(*magmaCipher)

	want := [][2]uint32{
		{0x76543210, 0x28da3b14}, {0x28da3b14, 0xb14337a5},
		{0xb14337a5, 0x633a7c68}, {0x633a7c68, 0xea89c02c},
		{0xea89c02c, 0x11fe726d}, {0x11fe726d, 0xad0310a4},
		{0xad0310a4, 0x37d97f25}, {0x37d97f25, 0x46324615},
		{0x46324615, 0xce995f2a}, {0xce995f2a, 0x93c1f449},
		{0x93c1f449, 0x4811c7ad}, {0x4811c7ad, 0xc4b3edca},
		{0xc4b3edca, 0x44ca5ce1}, {0x44ca5ce1, 0xfef51b68},
		{0xfef51b68, 0x2098cd86}, {0x2098cd86, 0x4f15b0bb},
		{0x4f15b0bb, 0xe32805bc}, {0xe32805bc, 0xe7116722},
		{0xe7116722, 0x89cadf21}, {0x89cadf21, 0xbac8444d},
		{0xbac8444d, 0x11263a21}, {0x11263a21, 0x625434c3},
		{0x625434c3, 0x8025c0a5}, {0x8025c0a5, 0xb0d66514},
		{0xb0d66514, 0x47b1d5f4},
	}

	src := mustHex(t, "fedcba9876543210")
	a1 := binary.BigEndian.Uint32(src[0:4])
	a0 := binary.BigEndian.Uint32(src[4:8])
	for i, w := range want {
		a1, a0 = a0, a1^g(a0, c.rk[i])
		if a1 != w[0] || a0 != w[1] {
			t.Fatalf("после раунда %d: (%08x, %08x), ожидалось (%08x, %08x)",
				i+1, a1, a0, w[0], w[1])
		}
	}
}

// Векторы режима простой замены из ГОСТ Р 34.13-2015, приложение А.2.1 —
// это четыре независимых применения базового алгоритма, поэтому они
// проверяют сам шифр, а не режим.
func TestECBVectors(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ plain, cipher string }{
		{"92def06b3c130a59", "2b073f0494f372a0"},
		{"db54c704f8189d20", "de70e715d3556e48"},
		{"4a98fb2e67a8024c", "11d8d9e9eacfbc1e"},
		{"8912409b17b57e41", "7c68260996c67efb"},
	}
	got := make([]byte, BlockSize)
	for i, c := range cases {
		blk.Encrypt(got, mustHex(t, c.plain))
		if want := mustHex(t, c.cipher); !bytes.Equal(got, want) {
			t.Errorf("блок %d: Encrypt = %x, ожидалось %x", i+1, got, want)
		}
		blk.Decrypt(got, mustHex(t, c.cipher))
		if want := mustHex(t, c.plain); !bytes.Equal(got, want) {
			t.Errorf("блок %d: Decrypt = %x, ожидалось %x", i+1, got, want)
		}
	}
}

func TestKeySizeError(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewCipher(make([]byte, n)); err == nil {
			t.Errorf("NewCipher с ключом %d байт: ошибка не возвращена", n)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	src := make([]byte, BlockSize)
	enc := make([]byte, BlockSize)
	dec := make([]byte, BlockSize)
	for i := 0; i < 512; i++ {
		binary.BigEndian.PutUint64(src, uint64(i)*0x9E3779B97F4A7C15)
		blk.Encrypt(enc, src)
		blk.Decrypt(dec, enc)
		if !bytes.Equal(dec, src) {
			t.Fatalf("round-trip не сошёлся для %x: получено %x", src, dec)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	blk, err := NewCipher(make([]byte, KeySize))
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, BlockSize)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blk.Encrypt(buf, buf)
	}
}
