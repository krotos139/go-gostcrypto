// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost28147

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func hx(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// Единственный публично опубликованный контрольный пример для режима
// имитовставки — из схемы экспорта ключа: Р 50.1.113-2016, приложение А
// (RFC 7836, приложение B, пример 11). Ключом там служит выработанный
// KEK, начальным значением — вектор seed.
func TestMACKnownAnswer(t *testing.T) {
	kek := hx(t, "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")
	data := hx(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	iv := hx(t, "af21434145656378")

	got, err := MAC(kek, ParamZ(), iv, data, 4)
	if err != nil {
		t.Fatal(err)
	}
	if want := hx(t, "be33f052"); !bytes.Equal(got, want) {
		t.Fatalf("имитовставка = %x, ожидалось %x", got, want)
	}
}

// refMAC — эталон по RFC 5830, раздел 8: блоки складываются с
// содержимым регистров по модулю 2 и прогоняются через первые
// шестнадцать раундов; имитовставка — старшие разряды N1.
func refMAC(t testing.TB, key []byte, iv, data []byte, size int) []byte {
	t.Helper()
	b, err := NewCipher(key, ParamZ())
	if err != nil {
		t.Fatal(err)
	}
	c := b.(*Cipher)

	var n1, n2 uint32
	if len(iv) == BlockSize {
		n1 = binary.LittleEndian.Uint32(iv[0:4])
		n2 = binary.LittleEndian.Uint32(iv[4:8])
	}

	// Неполный последний блок дополняется нулями.
	padded := append([]byte(nil), data...)
	if n := len(padded) % BlockSize; n != 0 {
		padded = append(padded, make([]byte, BlockSize-n)...)
	}

	for i := 0; i < len(padded); i += BlockSize {
		n1 ^= binary.LittleEndian.Uint32(padded[i : i+4])
		n2 ^= binary.LittleEndian.Uint32(padded[i+4 : i+8])
		// Шестнадцать раундов: подключи X0..X7 используются дважды.
		for r := 0; r < 16; r++ {
			n1, n2 = n2^c.f(n1, c.rk[r]), n1
		}
	}

	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], n1)
	return out[4-size : 4]
}

func TestMACMatchesReference(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*9 + 1)
	}
	iv := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	for _, n := range []int{0, 1, 7, 8, 9, 16, 17, 64, 100} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 3)
		}
		for _, size := range []int{1, 2, 3, 4} {
			for _, useIV := range []bool{false, true} {
				var vec []byte
				if useIV {
					vec = iv
				}
				got, err := MAC(key, ParamZ(), vec, data, size)
				if err != nil {
					t.Fatal(err)
				}
				want := refMAC(t, key, vec, data, size)
				if !bytes.Equal(got, want) {
					t.Fatalf("длина %d, size %d, iv %v: %x вместо %x", n, size, useIV, got, want)
				}
			}
		}
	}
}

// Укороченная имитовставка — это старшие разряды той же величины, а не
// самостоятельное значение.
func TestMACShortIsPrefixOfLong(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, KeySize)
	data := []byte("сообщение для имитовставки")

	full, err := MAC(key, ParamZ(), nil, data, 4)
	if err != nil {
		t.Fatal(err)
	}
	for size := 1; size <= 4; size++ {
		got, err := MAC(key, ParamZ(), nil, data, size)
		if err != nil {
			t.Fatal(err)
		}
		if want := full[4-size:]; !bytes.Equal(got, want) {
			t.Errorf("size %d: %x, ожидалось %x", size, got, want)
		}
	}
}

func TestMACChunked(t *testing.T) {
	key := bytes.Repeat([]byte{0x5C}, KeySize)
	data := make([]byte, 137)
	for i := range data {
		data[i] = byte(i * 13)
	}

	want, err := MAC(key, ParamZ(), nil, data, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []int{1, 3, 8, 9, 64} {
		m, err := NewMAC(key, ParamZ(), nil, 4)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(data); i += chunk {
			end := i + chunk
			if end > len(data) {
				end = len(data)
			}
			m.Write(data[i:end])
		}
		if got := m.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("куски по %d байт: %x вместо %x", chunk, got, want)
		}
	}
}

// Sum не должна менять состояние: повторный вызов даёт то же значение,
// а дозапись продолжает с того же места.
func TestMACSumDoesNotChangeState(t *testing.T) {
	key := bytes.Repeat([]byte{0x2A}, KeySize)
	m, err := NewMAC(key, ParamZ(), nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	m.Write([]byte("первая часть"))
	a := m.Sum(nil)
	b := m.Sum(nil)
	if !bytes.Equal(a, b) {
		t.Fatalf("повторный Sum дал другое значение: %x и %x", a, b)
	}

	m.Write([]byte("вторая часть"))
	whole, err := MAC(key, ParamZ(), nil, []byte("первая частьвторая часть"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Sum(nil); !bytes.Equal(got, whole) {
		t.Fatalf("после дозаписи: %x вместо %x", got, whole)
	}
}

// Имитовставка обязана зависеть от каждого входного значения.
func TestMACDependsOnEverything(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeySize)
	iv := bytes.Repeat([]byte{0x22}, BlockSize)
	data := []byte("контролируемые данные___")

	base, err := MAC(key, ParamZ(), iv, data, 4)
	if err != nil {
		t.Fatal(err)
	}

	otherKey := append([]byte(nil), key...)
	otherKey[0] ^= 0x01
	if v, _ := MAC(otherKey, ParamZ(), iv, data, 4); bytes.Equal(v, base) {
		t.Error("не зависит от ключа")
	}

	otherIV := append([]byte(nil), iv...)
	otherIV[0] ^= 0x01
	if v, _ := MAC(key, ParamZ(), otherIV, data, 4); bytes.Equal(v, base) {
		t.Error("не зависит от начального значения")
	}

	otherData := append([]byte(nil), data...)
	otherData[len(otherData)-1] ^= 0x01
	if v, _ := MAC(key, ParamZ(), iv, otherData, 4); bytes.Equal(v, base) {
		t.Error("не зависит от последнего байта данных")
	}

	if v, _ := MAC(key, ParamCryptoProA(), iv, data, 4); bytes.Equal(v, base) {
		t.Error("не зависит от набора подстановок")
	}

	// Нулевое начальное значение — это не то же самое, что отсутствие.
	if v, _ := MAC(key, ParamZ(), make([]byte, BlockSize), data, 4); !bytes.Equal(v, mustMAC(t, key, nil, data)) {
		t.Error("нулевой вектор и его отсутствие должны совпадать")
	}
}

func mustMAC(t testing.TB, key, iv, data []byte) []byte {
	t.Helper()
	v, err := MAC(key, ParamZ(), iv, data, 4)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMACParamValidation(t *testing.T) {
	key := make([]byte, KeySize)
	for _, size := range []int{-1, 0, 5, 8, 100} {
		if _, err := NewMAC(key, ParamZ(), nil, size); err != ErrMACSize {
			t.Errorf("size = %d: err = %v", size, err)
		}
	}
	for _, n := range []int{1, 7, 9, 16} {
		if _, err := NewMAC(key, ParamZ(), make([]byte, n), 4); err != ErrIVSize {
			t.Errorf("|iv| = %d: err = %v", n, err)
		}
	}
	if _, err := NewMAC(make([]byte, 16), ParamZ(), nil, 4); err == nil {
		t.Error("короткий ключ принят")
	}

	m, err := NewMAC(key, ParamZ(), nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if m.Size() != 3 {
		t.Errorf("Size() = %d", m.Size())
	}
	if m.BlockSize() != BlockSize {
		t.Errorf("BlockSize() = %d", m.BlockSize())
	}
}

func BenchmarkMAC(b *testing.B) {
	key := make([]byte, KeySize)
	data := make([]byte, 8192)
	m, err := NewMAC(key, ParamZ(), nil, 4)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Reset()
		m.Write(data)
		m.Sum(nil)
	}
}
