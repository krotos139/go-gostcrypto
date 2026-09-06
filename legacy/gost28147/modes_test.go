// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost28147

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

// RFC 5830 не содержит контрольных примеров для режимов гаммирования,
// поэтому проверка идёт от буквальной записи формул из разделов 6 и 7.
// Эталон ниже переписан с текста стандарта построчно, без буферизации и
// без работы с неполными блоками: он заведомо медленный и негодный для
// применения, зато очевидно соответствует формулам.

func refKey(t testing.TB) cipher.Block {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i * 5)
	}
	b, err := NewCipher(key, ParamZ())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// refGamma — эталон режима гаммирования (RFC 5830, раздел 6):
//
//	(Y0, Z0) = A(S)
//	Gc(i)    = A(Y[i-1] [+] C2, Z[i-1] [+]' C1)
//	Tc(i)    = Gc(i) (+) Tp(i)
func refGamma(b cipher.Block, iv, data []byte) []byte {
	var s [BlockSize]byte
	b.Encrypt(s[:], iv)
	y := binary.LittleEndian.Uint32(s[0:4])
	z := binary.LittleEndian.Uint32(s[4:8])

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += BlockSize {
		y = uint32((uint64(y) + c2) & 0xFFFFFFFF)
		sum := uint64(z) + c1
		if sum >= 0xFFFFFFFF {
			sum -= 0xFFFFFFFF
		}
		z = uint32(sum)

		var in, g [BlockSize]byte
		binary.LittleEndian.PutUint32(in[0:4], y)
		binary.LittleEndian.PutUint32(in[4:8], z)
		b.Encrypt(g[:], in[:])

		for j := 0; j < BlockSize && i+j < len(data); j++ {
			out[i+j] = data[i+j] ^ g[j]
		}
	}
	return out
}

// refCFB — эталон гаммирования с обратной связью (RFC 5830, раздел 7):
//
//	Gc(1) = A(S), Gc(i) = A(Tc(i-1))
//	Tc(i) = Gc(i) (+) Tp(i)
func refCFB(b cipher.Block, iv, data []byte, decrypt bool) []byte {
	state := make([]byte, BlockSize)
	copy(state, iv)

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += BlockSize {
		var g [BlockSize]byte
		b.Encrypt(g[:], state)

		n := BlockSize
		if i+n > len(data) {
			n = len(data) - i
		}
		for j := 0; j < n; j++ {
			out[i+j] = data[i+j] ^ g[j]
		}
		// В обратную связь уходит шифртекст: при зашифровании это
		// результат, при расшифровании — исходные данные.
		if decrypt {
			copy(state, data[i:i+n])
		} else {
			copy(state, out[i:i+n])
		}
	}
	return out
}

var modeLengths = []int{0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 200}

func TestGammaMatchesReference(t *testing.T) {
	b := refKey(t)
	iv := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	for _, n := range modeLengths {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 3)
		}
		st, err := NewGamma(b, iv)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, n)
		st.XORKeyStream(got, data)
		if want := refGamma(b, iv, data); !bytes.Equal(got, want) {
			t.Fatalf("длина %d:\n  получено %x\n  эталон   %x", n, got, want)
		}
	}
}

func TestCFBMatchesReference(t *testing.T) {
	b := refKey(t)
	iv := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	for _, n := range modeLengths {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 1)
		}

		enc, err := NewCFBEncrypter(b, iv)
		if err != nil {
			t.Fatal(err)
		}
		ct := make([]byte, n)
		enc.XORKeyStream(ct, data)
		if want := refCFB(b, iv, data, false); !bytes.Equal(ct, want) {
			t.Fatalf("зашифрование, длина %d:\n  получено %x\n  эталон   %x", n, ct, want)
		}

		dec, err := NewCFBDecrypter(b, iv)
		if err != nil {
			t.Fatal(err)
		}
		pt := make([]byte, n)
		dec.XORKeyStream(pt, ct)
		if !bytes.Equal(pt, data) {
			t.Fatalf("расшифрование, длина %d: %x вместо %x", n, pt, data)
		}
		if want := refCFB(b, iv, ct, true); !bytes.Equal(pt, want) {
			t.Fatalf("расшифрование, длина %d: расходится с эталоном", n)
		}
	}
}

// В режиме гаммирования гамма не зависит от текста: сумма двух шифртекстов
// обязана совпадать с суммой открытых текстов. Если бы обратная связь
// случайно затесалась в реализацию, это свойство сломалось бы.
func TestGammaIsIndependentOfPlaintext(t *testing.T) {
	b := refKey(t)
	iv := bytes.Repeat([]byte{0x5A}, BlockSize)

	p1 := make([]byte, 100)
	p2 := make([]byte, 100)
	for i := range p1 {
		p1[i] = byte(i)
		p2[i] = byte(255 - i)
	}

	enc := func(p []byte) []byte {
		st, err := NewGamma(b, iv)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(p))
		st.XORKeyStream(out, p)
		return out
	}
	c1, c2 := enc(p1), enc(p2)
	for i := range c1 {
		if c1[i]^c2[i] != p1[i]^p2[i] {
			t.Fatalf("гамма зависит от текста в байте %d", i)
		}
	}

	// У режима с обратной связью такого свойства быть не должно.
	cfb := func(p []byte) []byte {
		st, err := NewCFBEncrypter(b, iv)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(p))
		st.XORKeyStream(out, p)
		return out
	}
	f1, f2 := cfb(p1), cfb(p2)
	same := true
	for i := range f1 {
		if f1[i]^f2[i] != p1[i]^p2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("обратная связь не влияет на шифртекст")
	}
	// Первый блок обязан совпадать: обратная связь начинает действовать
	// только со второго.
	for i := 0; i < BlockSize; i++ {
		if f1[i]^f2[i] != p1[i]^p2[i] {
			t.Fatalf("первый блок уже расходится в байте %d", i)
		}
	}
}

// Поточный шифр не должен зависеть от того, какими кусками ему подают
// данные, и обязан работать "на месте".
func TestModesChunkedAndInPlace(t *testing.T) {
	b := refKey(t)
	iv := bytes.Repeat([]byte{0x3C}, BlockSize)
	data := make([]byte, 137)
	for i := range data {
		data[i] = byte(i * 11)
	}

	for _, mode := range []struct {
		name string
		new  func() (cipher.Stream, error)
	}{
		{"гаммирование", func() (cipher.Stream, error) { return NewGamma(b, iv) }},
		{"с обратной связью", func() (cipher.Stream, error) { return NewCFBEncrypter(b, iv) }},
	} {
		t.Run(mode.name, func(t *testing.T) {
			st, err := mode.new()
			if err != nil {
				t.Fatal(err)
			}
			whole := make([]byte, len(data))
			st.XORKeyStream(whole, data)

			for _, chunk := range []int{1, 3, 8, 9, 64} {
				st, err := mode.new()
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(data))
				for i := 0; i < len(data); i += chunk {
					end := i + chunk
					if end > len(data) {
						end = len(data)
					}
					st.XORKeyStream(got[i:end], data[i:end])
				}
				if !bytes.Equal(got, whole) {
					t.Errorf("куски по %d байт дают другой результат", chunk)
				}
			}

			st, err = mode.new()
			if err != nil {
				t.Fatal(err)
			}
			inPlace := append([]byte(nil), data...)
			st.XORKeyStream(inPlace, inPlace)
			if !bytes.Equal(inPlace, whole) {
				t.Error("работа на месте даёт другой результат")
			}
		})
	}
}

func TestModeParamValidation(t *testing.T) {
	b := refKey(t)
	for _, n := range []int{0, 1, 7, 9, 16} {
		if _, err := NewGamma(b, make([]byte, n)); err != ErrIVSize {
			t.Errorf("гаммирование, |iv| = %d: err = %v", n, err)
		}
		if _, err := NewCFBEncrypter(b, make([]byte, n)); err != ErrIVSize {
			t.Errorf("обратная связь, |iv| = %d: err = %v", n, err)
		}
	}

	// Шифр с другим размером блока не подходит: константы C1 и C2
	// определены только для 64-битного блока.
	if _, err := NewGamma(wideBlock{}, make([]byte, BlockSize)); err != ErrBlockSize {
		t.Errorf("чужой размер блока: err = %v", err)
	}
}

// wideBlock подставляет шифр с блоком не того размера.
type wideBlock struct{}

func (wideBlock) BlockSize() int          { return 16 }
func (wideBlock) Encrypt(dst, src []byte) {}
func (wideBlock) Decrypt(dst, src []byte) {}

// addMod32m1 определено на всей области значений: проверяются края и
// перенос через 2^32-1.
func TestAddMod32m1(t *testing.T) {
	cases := []struct{ a, b, want uint32 }{
		{0, 0, 0},
		{1, 2, 3},
		{0xFFFFFFFE, 1, 0}, // ровно 2^32-1 обращается в ноль
		{0xFFFFFFFE, 2, 1}, // перенос
		{0xFFFFFFFF, 1, 1}, // 2^32 - (2^32-1) = 1
		{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
		{0x7FFFFFFF, 0x80000000, 0},
	}
	for _, c := range cases {
		if got := addMod32m1(c.a, c.b); got != c.want {
			t.Errorf("addMod32m1(%#x, %#x) = %#x, ожидалось %#x", c.a, c.b, got, c.want)
		}
	}
}

func BenchmarkGamma(b *testing.B) {
	blk := refKey(b)
	iv := make([]byte, BlockSize)
	buf := make([]byte, 8192)
	st, err := NewGamma(blk, iv)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.XORKeyStream(buf, buf)
	}
}
