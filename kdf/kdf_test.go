// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package kdf

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

const (
	kIn   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	label = "26bdb878"
	seed  = "af21434145656378"
)

// Р 50.1.113-2016, приложение А (RFC 7836, приложение B, пример 9).
func TestDerive(t *testing.T) {
	want := mustHex(t, "a1aa5f7de402d7b3d323f2991c8d4534"+
		"013137010a83754fd0af6d7cd4922ed9")
	got := Derive(mustHex(t, kIn), mustHex(t, label), mustHex(t, seed))
	if !bytes.Equal(got, want) {
		t.Fatalf("KDF = %x\n  ожидалось %x", got, want)
	}
}

// RFC 7836, приложение B, пример 10: R = 1, L = 512, два блока.
func TestDeriveTree(t *testing.T) {
	k1 := "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b"
	k2 := "074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
	want := mustHex(t, k1+k2)

	got, err := DeriveTree(mustHex(t, kIn), mustHex(t, label), mustHex(t, seed), 1, 512)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("KDF_TREE = %x\n  ожидалось %x", got, want)
	}
}

// Derive — частный случай DeriveTree при R = 1 и L = 256.
func TestDeriveIsSpecialCase(t *testing.T) {
	tree, err := DeriveTree(mustHex(t, kIn), mustHex(t, label), mustHex(t, seed), 1, 256)
	if err != nil {
		t.Fatal(err)
	}
	plain := Derive(mustHex(t, kIn), mustHex(t, label), mustHex(t, seed))
	if !bytes.Equal(tree, plain) {
		t.Fatalf("DeriveTree(R=1, L=256) = %x, Derive = %x", tree, plain)
	}
	// Первый блок KDF_TREE при L = 512 отличается от результата при
	// L = 256: длина входит в вычисляемое значение.
	long, err := DeriveTree(mustHex(t, kIn), mustHex(t, label), mustHex(t, seed), 1, 512)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(long[:32], plain) {
		t.Fatal("значение L не участвует в вычислении")
	}
}

// [L]_b записывается без ведущих нулей.
func TestLenBytes(t *testing.T) {
	cases := []struct {
		v    uint64
		want string
	}{
		{256, "0100"},
		{512, "0200"},
		{1, "01"},
		{255, "ff"},
		{65536, "010000"},
	}
	for _, c := range cases {
		if got := lenBytes(c.v); !bytes.Equal(got, mustHex(t, c.want)) {
			t.Errorf("lenBytes(%d) = %x, ожидалось %s", c.v, got, c.want)
		}
	}
}

func TestDeriveTreeParams(t *testing.T) {
	k, l, s := mustHex(t, kIn), mustHex(t, label), mustHex(t, seed)

	for _, r := range []int{-1, 0, 5, 100} {
		if _, err := DeriveTree(k, l, s, r, 256); err != ErrRParam {
			t.Errorf("R = %d: err = %v", r, err)
		}
	}
	for _, bits := range []int{0, -8, 7, 100} {
		if _, err := DeriveTree(k, l, s, 1, bits); err != ErrLength {
			t.Errorf("L = %d: err = %v", bits, err)
		}
	}
	// При R = 1 предел равен 256*(2^8-1) = 65280 бит.
	if _, err := DeriveTree(k, l, s, 1, 65280); err != nil {
		t.Errorf("L = 65280 при R = 1 отвергнут: %v", err)
	}
	if _, err := DeriveTree(k, l, s, 1, 65280+8); err != ErrLength {
		t.Errorf("L сверх предела принят")
	}
}

func TestDeriveTreeLengths(t *testing.T) {
	k, l, s := mustHex(t, kIn), mustHex(t, label), mustHex(t, seed)
	for _, bits := range []int{8, 128, 256, 264, 512, 1024, 2048} {
		got, err := DeriveTree(k, l, s, 2, bits)
		if err != nil {
			t.Fatalf("L = %d: %v", bits, err)
		}
		if len(got) != bits/8 {
			t.Fatalf("L = %d: длина %d байт", bits, len(got))
		}
	}
}

// --- PBKDF2 ---------------------------------------------------------------

// Р 50.1.111-2016, приложение А. Псевдослучайная функция —
// HMAC_GOSTR3411_2012_512.
func TestPBKDF2(t *testing.T) {
	cases := []struct {
		password, salt string
		iter, dkLen    int
		want           string
	}{
		{
			"password", "salt", 1, 64,
			"64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d" +
				"2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47",
		},
		{
			"password", "salt", 2, 64,
			"5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4" +
				"d34b2b8fbd2c4e89d54d46f50e47d45bbac3015717431 19e8d3c42ba66d348de",
		},
		{
			"password", "salt", 4096, 64,
			"e52deb9a2d2aaff4e2ac9d47a41f34c20376591c67807f0477e32549dc341bc7" +
				"867c09841b6d58e29d0347c996301d55df0d34e47cf68f4e3c2cdaf1d9ab86c3",
		},
		{
			"passwordPASSWORDpassword",
			"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 100,
			"b2d8f1245fc4d29274802057e4b54e0a0753aa22fc53760b301cf008679e58fe" +
				"4bee9addcae99ba2b0b20f431a9c5e50f395c89387d0945aedeca6eb4015dfc2" +
				"bd2421ee9bb71183ba882ceebfef259f33f9e27dc6178cb89dc37428cf9cc52a" +
				"2baa2d3a",
		},
		{
			"pass\x00word", "sa\x00lt", 4096, 64,
			"50df062885b69801a3c10248eb0a27ab6e522ffeb20c991c660f001475d73a4e" +
				"167f782c18e97e92976d9c1d970831ea78ccb879f67068cdac19107408 44e830",
		},
	}

	for _, c := range cases {
		want := mustHex(t, stripSpaces(c.want))
		got := PBKDF2([]byte(c.password), []byte(c.salt), c.iter, c.dkLen)
		if !bytes.Equal(got, want) {
			t.Errorf("PBKDF2(%q, %q, %d, %d) =\n  %x\n  ожидалось\n  %x",
				c.password, c.salt, c.iter, c.dkLen, got, want)
		}
	}
}

func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// Ключ произвольной длины должен быть префиксом более длинного: PBKDF2
// вырабатывает блоки последовательно и усекает только последний.
func TestPBKDF2Prefix(t *testing.T) {
	pw, salt := []byte("password"), []byte("salt")
	full := PBKDF2(pw, salt, 4, 200)
	for _, n := range []int{1, 32, 63, 64, 65, 128, 199, 200} {
		got := PBKDF2(pw, salt, 4, n)
		if !bytes.Equal(got, full[:n]) {
			t.Fatalf("длина %d: результат не является префиксом", n)
		}
	}
}

func TestPBKDF2Variants(t *testing.T) {
	pw, salt := []byte("password"), []byte("salt")
	if bytes.Equal(PBKDF2(pw, salt, 2, 32), PBKDF2With256(pw, salt, 2, 32)) {
		t.Fatal("варианты на 512 и 256 битах дали одинаковый результат")
	}
	if bytes.Equal(PBKDF2(pw, salt, 1, 32), PBKDF2(pw, salt, 2, 32)) {
		t.Fatal("число итераций не влияет на результат")
	}
	if bytes.Equal(PBKDF2(pw, salt, 2, 32), PBKDF2(pw, []byte("Salt"), 2, 32)) {
		t.Fatal("соль не влияет на результат")
	}
}

func BenchmarkPBKDF2(b *testing.B) {
	pw, salt := []byte("password"), []byte("salt")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PBKDF2(pw, salt, 1000, 32)
	}
}
