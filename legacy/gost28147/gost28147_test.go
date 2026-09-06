// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost28147

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

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

func named() map[string]*SBox {
	return map[string]*SBox{
		"Test":          ParamTest(),
		"CryptoPro-A":   ParamCryptoProA(),
		"CryptoPro-B":   ParamCryptoProB(),
		"CryptoPro-C":   ParamCryptoProC(),
		"CryptoPro-D":   ParamCryptoProD(),
		"param-Z":       ParamZ(),
		"HashTest":      ParamHashTest(),
		"HashCryptoPro": ParamHashCryptoPro(),
	}
}

func TestNamedSBoxesAreValid(t *testing.T) {
	for name, s := range named() {
		if !s.Valid() {
			t.Errorf("%s: не все таблицы являются перестановками", name)
		}
	}
}

// Наборы должны отличаться друг от друга: совпадение означало бы ошибку
// переноса.
func TestNamedSBoxesDiffer(t *testing.T) {
	seen := map[SBox]string{}
	for name, s := range named() {
		if prev, ok := seen[*s]; ok {
			t.Errorf("наборы %s и %s совпадают", name, prev)
		}
		seen[*s] = name
	}
}

// Возвращаемые наборы должны быть копиями: правка одного не может
// испортить другой.
func TestParamsReturnCopies(t *testing.T) {
	a := ParamZ()
	a[0][0] ^= 0xf
	if b := ParamZ(); *a == *b {
		t.Fatal("ParamZ вернул общую таблицу, а не копию")
	}
}

// Раскладка упакованного набора проверяется на том, что RFC 4357 и
// RFC 5831 задают один и тот же тестовый набор подстановок: в первом он
// упакован в 64 байта, во втором напечатан явной таблицей.
func TestUnpackSBox(t *testing.T) {
	packed := mustHex(t,
		"4e5764d1ab8dcbbf941a7a4d2cd11010d6a057358d38f2f70f49d15aea2f8d94"+
			"62ee4309b3f4a6a218c698e3c17ce57e706b0966f7023c8b5595bf2839b32ecc")
	got, err := UnpackSBox(packed)
	if err != nil {
		t.Fatal(err)
	}
	if want := ParamHashTest(); *got != *want {
		t.Fatalf("разбор дал другой набор:\n  %v\n  ожидалось %v", *got, *want)
	}

	for _, bad := range [][]byte{nil, packed[:63], append(append([]byte(nil), packed...), 0)} {
		if _, err := UnpackSBox(bad); err != ErrSBox {
			t.Errorf("длина %d: err = %v", len(bad), err)
		}
	}
	// Испорченный набор перестаёт быть перестановкой и должен отвергаться.
	broken := append([]byte(nil), packed...)
	broken[0] = broken[8]
	if _, err := UnpackSBox(broken); err != ErrSBox {
		t.Errorf("испорченный набор принят: err = %v", err)
	}
}

// reverse разворачивает срез.
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// wordReverse разворачивает каждую четвёрку байт по отдельности.
func wordReverse(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := 0; i+4 <= len(out); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = out[i+3], out[i+2], out[i+1], out[i]
	}
	return out
}

// "Магма" — это тот же алгоритм с набором param-Z и обратным порядком
// байт. Поскольку "Магма" уже сверена с контрольными примерами
// ГОСТ Р 34.12-2015, это даёт независимую проверку данной реализации.
//
// Соответствие получается такое: подключи совпадают, если каждое
// четырёхбайтовое слово ключа развёрнуто, а блок данных развёрнут целиком;
// результат тоже оказывается развёрнутым.
func TestMatchesMagma(t *testing.T) {
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	m, err := magma.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewCipher(wordReverse(key), ParamZ())
	if err != nil {
		t.Fatal(err)
	}

	block := make([]byte, BlockSize)
	magmaOut := make([]byte, BlockSize)
	gostOut := make([]byte, BlockSize)

	for i := 0; i < 256; i++ {
		binary.BigEndian.PutUint64(block, uint64(i)*0x9E3779B97F4A7C15)

		m.Encrypt(magmaOut, block)
		g.Encrypt(gostOut, reverse(block))

		if !bytes.Equal(reverse(gostOut), magmaOut) {
			t.Fatalf("блок %x:\n  ГОСТ 28147-89 (развёрнут) = %x\n  Магма                    = %x",
				block, reverse(gostOut), magmaOut)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i * 7)
	}
	for name, sbox := range named() {
		c, err := NewCipher(key, sbox)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		src := make([]byte, BlockSize)
		enc := make([]byte, BlockSize)
		dec := make([]byte, BlockSize)
		for i := 0; i < 128; i++ {
			binary.LittleEndian.PutUint64(src, uint64(i)*0xC2B2AE3D27D4EB4F)
			c.Encrypt(enc, src)
			c.Decrypt(dec, enc)
			if !bytes.Equal(dec, src) {
				t.Fatalf("%s: round-trip не сошёлся для %x", name, src)
			}
		}
	}
}

// Разные наборы подстановок обязаны давать разный шифртекст.
func TestSBoxAffectsResult(t *testing.T) {
	key := make([]byte, KeySize)
	block := mustHex(t, "0011223344556677")
	seen := map[string]string{}
	for name, sbox := range named() {
		c, err := NewCipher(key, sbox)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, BlockSize)
		c.Encrypt(out, block)
		if prev, ok := seen[string(out)]; ok {
			t.Errorf("наборы %s и %s дали одинаковый шифртекст", name, prev)
		}
		seen[string(out)] = name
	}
}

func TestSetKey(t *testing.T) {
	c, err := NewSchedule(ParamZ())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 16, 31, 33} {
		if err := c.SetKey(make([]byte, n)); err == nil {
			t.Errorf("ключ длины %d принят", n)
		}
	}

	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	if err := c.SetKey(key); err != nil {
		t.Fatal(err)
	}
	block := mustHex(t, "0011223344556677")
	viaSetKey := make([]byte, BlockSize)
	c.Encrypt(viaSetKey, block)

	direct, err := NewCipher(key, ParamZ())
	if err != nil {
		t.Fatal(err)
	}
	viaNew := make([]byte, BlockSize)
	direct.Encrypt(viaNew, block)

	if !bytes.Equal(viaSetKey, viaNew) {
		t.Fatal("SetKey и NewCipher дали разный результат")
	}
}

func TestErrors(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewCipher(make([]byte, n), ParamZ()); err == nil {
			t.Errorf("ключ длины %d принят", n)
		}
	}
	if _, err := NewCipher(make([]byte, KeySize), nil); err != ErrSBox {
		t.Errorf("nil-набор: err = %v", err)
	}
	var broken SBox
	if _, err := NewCipher(make([]byte, KeySize), &broken); err != ErrSBox {
		t.Errorf("нулевой набор принят: err = %v", err)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	c, _ := NewCipher(make([]byte, KeySize), ParamZ())
	buf := make([]byte, BlockSize)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}
