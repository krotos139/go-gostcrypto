// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package kuznyechik

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mustBlock(t testing.TB, s string) block {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	if len(b) != BlockSize {
		t.Fatalf("hex %q: длина %d, ожидалось %d", s, len(b), BlockSize)
	}
	var blk block
	copy(blk[:], b)
	return blk
}

// roundKey восстанавливает раундовый ключ из машинного представления:
// после перехода на объединённые таблицы ключи хранятся парами слов.
func roundKey(c *kuznyechikCipher, i int) block {
	var b block
	binary.BigEndian.PutUint64(b[0:8], c.ek[i][0])
	binary.BigEndian.PutUint64(b[8:16], c.ek[i][1])
	return b
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// pi должна быть биекцией; это же гарантирует корректность выведенной piInv.
func TestPiIsBijection(t *testing.T) {
	var seen [256]bool
	for _, v := range pi {
		if seen[v] {
			t.Fatalf("pi не биективна: значение %d встречается дважды", v)
		}
		seen[v] = true
	}
	for i := 0; i < 256; i++ {
		if piInv[pi[i]] != byte(i) {
			t.Fatalf("piInv(pi(%d)) = %d", i, piInv[pi[i]])
		}
	}
}

// Контрольные значения умножения в поле: kappa[6] = kappa[8] = kappa[15] = 1,
// значит соответствующие таблицы тождественны.
func TestGFMulIdentity(t *testing.T) {
	for x := 0; x < 256; x++ {
		if got := gfMul(1, byte(x)); got != byte(x) {
			t.Fatalf("gfMul(1, %d) = %d", x, got)
		}
	}
}

// ГОСТ Р 34.12-2015, приложение А.1.1 (RFC 7801, 5.1).
func TestTransformS(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ffeeddccbbaa99881122334455667700", "b66cd8887d38e8d77765aeea0c9a7efc"},
		{"b66cd8887d38e8d77765aeea0c9a7efc", "559d8dd7bd06cbfe7e7b262523280d39"},
		{"559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b"},
		{"0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda"},
	}
	for _, c := range cases {
		b := mustBlock(t, c.in)
		sTransform(&b)
		if want := mustBlock(t, c.want); b != want {
			t.Errorf("S(%s) = %x, ожидалось %s", c.in, b, c.want)
		}
		// Обратное преобразование должно возвращать исходное значение.
		sTransformInv(&b)
		if want := mustBlock(t, c.in); b != want {
			t.Errorf("S^-1(S(%s)) = %x", c.in, b)
		}
	}
}

// ГОСТ Р 34.12-2015, приложение А.1.2 (RFC 7801, 5.2).
func TestTransformR(t *testing.T) {
	cases := []struct{ in, want string }{
		{"00000000000000000000000000000100", "94000000000000000000000000000001"},
		{"94000000000000000000000000000001", "a5940000000000000000000000000000"},
		{"a5940000000000000000000000000000", "64a59400000000000000000000000000"},
		{"64a59400000000000000000000000000", "0d64a594000000000000000000000000"},
	}
	for _, c := range cases {
		b := mustBlock(t, c.in)
		r(&b)
		if want := mustBlock(t, c.want); b != want {
			t.Errorf("R(%s) = %x, ожидалось %s", c.in, b, c.want)
		}
		rInv(&b)
		if want := mustBlock(t, c.in); b != want {
			t.Errorf("R^-1(R(%s)) = %x", c.in, b)
		}
	}
}

// ГОСТ Р 34.12-2015, приложение А.1.3 (RFC 7801, 5.3).
func TestTransformL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"64a59400000000000000000000000000", "d456584dd0e3e84cc3166e4b7fa2890d"},
		{"d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a"},
		{"79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13"},
		{"0e93691a0cfc60408b7b68f66b513c13", "e6a8094fee0aa204fd97bcb0b44b8580"},
	}
	for _, c := range cases {
		b := mustBlock(t, c.in)
		lTransform(&b)
		if want := mustBlock(t, c.want); b != want {
			t.Errorf("L(%s) = %x, ожидалось %s", c.in, b, c.want)
		}
		lTransformInv(&b)
		if want := mustBlock(t, c.in); b != want {
			t.Errorf("L^-1(L(%s)) = %x", c.in, b)
		}
	}
}

const testKey = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"

// ГОСТ Р 34.12-2015, приложение А.1.4 (RFC 7801, 5.4).
func TestKeySchedule(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"8899aabbccddeeff0011223344556677",
		"fedcba98765432100123456789abcdef",
		"db31485315694343228d6aef8cc78c44",
		"3d4553d8e9cfec6815ebadc40a9ffd04",
		"57646468c44a5e28d3e59246f429f1ac",
		"bd079435165c6432b532e82834da581b",
		"51e640757e8745de705727265a0098b1",
		"5a7925017b9fdd3ed72a91a22286f984",
		"bb44e25378c73123a5f32f73cdb6e517",
		"72e9dd7416bcf45b755dbaa88e4a4043",
	}
	c := blk.(*kuznyechikCipher)
	for i, w := range want {
		if got, exp := roundKey(c, i), mustBlock(t, w); got != exp {
			t.Errorf("K_%d = %x, ожидалось %s", i+1, got, w)
		}
	}
}

// Первые итерационные константы, ГОСТ Р 34.12-2015, приложение А.1.4.
func TestIterationConstants(t *testing.T) {
	want := []string{
		"6ea276726c487ab85d27bd10dd849401",
		"dc87ece4d890f4b3ba4eb92079cbeb02",
		"b2259a96b4d88e0be7690430a44f7f03",
		"7bcd1b0b73e32ba5b79cb140f2551504",
		"156f6d791fab511deabb0c502fd18105",
		"a74af7efab73df160dd208608b9efe06",
		"c9e8819dc73ba5ae50f5b570561a6a07",
		"f6593616e6055689adfba18027aa2a08",
	}
	for i, w := range want {
		var v block
		v[BlockSize-1] = byte(i + 1)
		lTransform(&v)
		if exp := mustBlock(t, w); v != exp {
			t.Errorf("C_%d = %x, ожидалось %s", i+1, v, w)
		}
	}
}

// ГОСТ Р 34.12-2015, приложения А.1.5 и А.1.6 (RFC 7801, 5.5 и 5.6).
func TestCipherKAT(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	plain := mustHex(t, "1122334455667700ffeeddccbbaa9988")
	ciph := mustHex(t, "7f679d90bebc24305a468d42b9d4edcd")

	got := make([]byte, BlockSize)
	blk.Encrypt(got, plain)
	if !bytes.Equal(got, ciph) {
		t.Errorf("Encrypt = %x, ожидалось %x", got, ciph)
	}
	blk.Decrypt(got, ciph)
	if !bytes.Equal(got, plain) {
		t.Errorf("Decrypt = %x, ожидалось %x", got, plain)
	}
}

// Пораундовая сверка зашифрования: RFC 7801, 5.5.
func TestEncryptRounds(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	c := blk.(*kuznyechikCipher)

	want := []string{
		"e297b686e355b0a1cf4a2f9249140830",
		"285e497a0862d596b36f4258a1c69072",
		"0187a3a429b567841ad50d29207cc34e",
		"ec9bdba057d4f4d77c5d70619dcad206",
		"1357fd11de9257290c2a1473eb6bcde1",
		"28ae31e7d4c2354261027ef0b32897df",
		"07e223d56002c013d3f5e6f714b86d2d",
		"cd8ef6cd97e0e092a8e4cca61b38bf65",
		"0d8e40e4a800d06b2f1b37ea379ead8e",
	}

	tb := mustBlock(t, "1122334455667700ffeeddccbbaa9988")
	for i, w := range want {
		k := roundKey(c, i)
		xorBlock(&tb, &k)
		sTransform(&tb)
		lTransform(&tb)
		if exp := mustBlock(t, w); tb != exp {
			t.Fatalf("после LSX[K_%d]: %x, ожидалось %s", i+1, tb, w)
		}
	}
}

// Пораундовая сверка расшифрования: RFC 7801, 5.6.
func TestDecryptRounds(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	c := blk.(*kuznyechikCipher)

	tb := mustBlock(t, "7f679d90bebc24305a468d42b9d4edcd")
	k9 := roundKey(c, 9)
	xorBlock(&tb, &k9)
	if exp := mustBlock(t, "0d8e40e4a800d06b2f1b37ea379ead8e"); tb != exp {
		t.Fatalf("X[K_10](b) = %x", tb)
	}
	lTransformInv(&tb)
	if exp := mustBlock(t, "8a6b930a52211b45c5baa43ff8b91319"); tb != exp {
		t.Fatalf("L^-1 X[K_10](b) = %x", tb)
	}
	sTransformInv(&tb)
	if exp := mustBlock(t, "76ca149eef27d1b10d17e3d5d68e5a72"); tb != exp {
		t.Fatalf("S^-1 L^-1 X[K_10](b) = %x", tb)
	}

	want := []string{
		"5d9b06d41b9d1d2d04df7755363e94a9",
		"79487192aa45709c115559d6e9280f6e",
		"ae506924c8ce331bb918fc5bdfb195fa",
		"bbffbfc8939eaaffafb8e22769e323aa",
		"3cc2f07cc07a8bec0f3ea0ed2ae33e4a",
		"f36f01291d0b96d591e228b72d011c36",
		"1c4b0c1e950182b1ce696af5c0bfc5df",
		"99bb99ff99bb99ffffffffffffffffff",
	}
	for i, w := range want {
		idx := 8 - i // K_9, K_8, ..., K_2
		k := roundKey(c, idx)
		xorBlock(&tb, &k)
		lTransformInv(&tb)
		sTransformInv(&tb)
		if exp := mustBlock(t, w); tb != exp {
			t.Fatalf("шаг %d (K_%d): %x, ожидалось %s", i+1, idx+1, tb, w)
		}
	}
}

// Векторы режима простой замены из ГОСТ Р 34.13-2015, приложение А.1.1 —
// четыре независимых применения базового алгоритма.
func TestECBVectors(t *testing.T) {
	blk, err := NewCipher(mustHex(t, testKey))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ plain, cipher string }{
		{"1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"},
		{"00112233445566778899aabbcceeff0a", "b429912c6e0032f9285452d76718d08b"},
		{"112233445566778899aabbcceeff0a00", "f0ca33549d247ceef3f5a5313bd4b157"},
		{"2233445566778899aabbcceeff0a0011", "d0b09ccde830b9eb3a02c4c5aa8ada98"},
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
		binary.BigEndian.PutUint64(src[8:], uint64(i)*0xC2B2AE3D27D4EB4F)
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

func BenchmarkDecrypt(b *testing.B) {
	blk, err := NewCipher(make([]byte, KeySize))
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, BlockSize)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blk.Decrypt(buf, buf)
	}
}

func BenchmarkNewCipher(b *testing.B) {
	key := make([]byte, KeySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewCipher(key); err != nil {
			b.Fatal(err)
		}
	}
}
