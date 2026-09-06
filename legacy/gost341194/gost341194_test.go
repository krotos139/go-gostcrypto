// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost341194

import (
	"bytes"
	"encoding/hex"
	"hash"
	"testing"

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

// revHex разбирает запись стандарта и разворачивает её в порядок потока:
// в RFC 5831 все векторы напечатаны старшим разрядом влево.
func revHex(t testing.TB, s string) []byte {
	t.Helper()
	b := mustHex(t, s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// Контрольные примеры из RFC 5831, п. 7.3, в исходной записи стандарта.
// Начальное значение h0 нулевое, подстановки — из п. 7.1.
const (
	m1Std = "73657479622032333D687467" +
		"6E656C202C6567617373656D2073692073696854"
	h1Std = "FAFF37A615A816691CFF3EF8B68CA247" +
		"E09525F39F8119832EB81975D366C4B1"

	m2Std = "736574796220303520" +
		"3D20687467" +
		"6E656C2073616820" +
		"6567617373656D20" +
		"6C616E696769726F" +
		"2065687420657" +
		"36F70707553"
	h2Std = "0852F5623B89DD57AEB4781FE54DF14E" +
		"EAFBC1350613763A0D770AA657BA1A47"
)

// Первое, что надо зафиксировать: сообщения в стандарте — обычные
// ASCII-строки, напечатанные задом наперёд. Если это не так, остальные
// проверки бессмысленны.
func TestStandardHexIsReversed(t *testing.T) {
	if got, want := string(revHex(t, m1Std)), "This is message, length=32 bytes"; got != want {
		t.Fatalf("M1 = %q, ожидалось %q", got, want)
	}
	if got, want := string(revHex(t, m2Std)),
		"Suppose the original message has length = 50 bytes"; got != want {
		t.Fatalf("M2 = %q, ожидалось %q", got, want)
	}
}

// RFC 5831, п. 7.3.1 и 7.3.2.
func TestKAT(t *testing.T) {
	cases := []struct {
		name    string
		msg     string
		want    string
		wantLen int
	}{
		{"пример 1, 32 байта", m1Std, h1Std, 32},
		{"пример 2, 50 байт", m2Std, h2Std, 50},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := revHex(t, c.msg)
			if len(msg) != c.wantLen {
				t.Fatalf("длина сообщения %d, ожидалось %d", len(msg), c.wantLen)
			}
			h := NewTest()
			h.Write(msg)
			if got, want := h.Sum(nil), revHex(t, c.want); !bytes.Equal(got, want) {
				t.Fatalf("хэш = %x\n  ожидалось %x", got, want)
			}
		})
	}
}

// Промежуточные ключи первой свёртки chi(M, H) из примера 7.3.1: они
// локализуют ошибку в выработке ключей, а K[3] и K[4] дополнительно
// проверяют константу C[3].
//
// Опечатка в RFC 5831. В напечатанном значении K[1] четвёрки байт
// "326c6568" и "79676120" переставлены местами; ниже записан исправленный
// порядок. Это RFC Errata 2863 со статусом Verified. K[2], K[3] и K[4]
// в RFC приведены верно и сверяются дословно.
func TestKeyGeneration(t *testing.T) {
	want := []string{
		"733D2C20" + "65686573" + "74746769" + "79676120" +
			"626E7373" + "20657369" + "326C6568" + "33206D54",
		"110C733D0D166568130E7474064179671D00626E161A2065090D326C4D393320",
		"80B111F3730DF216850013F1C7E1F941620C1DFF3ABAE91A3FA109F2F513B239",
		"A0E2804EFF1B73F2ECE27A00E7B8C7E1EE1D620CAC0CC5BAA804C05EA18B0AEC",
	}

	h, err := New(gost28147.ParamHashTest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := h.(*digest)

	var m vec
	copy(m[:], revHex(t, m1Std)) // сообщение ровно в один блок
	got := d.keys(m)

	for i, w := range want {
		if !bytes.Equal(got[i][:], revHex(t, w)) {
			t.Errorf("K[%d] = %x\n  ожидалось %x", i+1, got[i], revHex(t, w))
		}
	}
}

// Константа C[3] должна совпадать с записью в п. 5.1 стандарта.
func TestC3(t *testing.T) {
	want := revHex(t, "ff00ffff000000ffff0000ff00ffff00"+
		"00ff00ff00ff00ffff00ff00ff00ff00")
	if !bytes.Equal(c3[:], want) {
		t.Fatalf("C[3] = %x\n  ожидалось %x", c3, want)
	}
}

// Перестановка P должна быть перестановкой.
func TestPermPIsPermutation(t *testing.T) {
	var seen [Size]bool
	for _, v := range permP {
		if int(v) >= Size || seen[v] {
			t.Fatalf("permP не является перестановкой: повтор %d", v)
		}
		seen[v] = true
	}
}

// Результат не должен зависеть от нарезки данных между вызовами Write.
// Особое внимание границам блока: 31, 32, 33 байта.
func TestChunkedWrites(t *testing.T) {
	msg := revHex(t, m2Std)
	h := NewTest()
	h.Write(msg)
	want := h.Sum(nil)

	for _, chunk := range []int{1, 2, 7, 16, 31, 32, 33, 49, 50} {
		h := NewTest()
		for off := 0; off < len(msg); off += chunk {
			h.Write(msg[off:min(off+chunk, len(msg))])
		}
		if got := h.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("куски по %d: %x", chunk, got)
		}
	}
}

// Сообщение, кратное размеру блока, обрабатывается особым образом:
// последний полный блок идёт через шаг 2, а не шаг 3, поэтому лишней
// свёртки с нулевым блоком быть не должно.
func TestLengthsAroundBlockBoundary(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i*13 + 5)
	}
	seen := map[string]int{}
	for n := 0; n <= 130; n++ {
		h := NewTest()
		h.Write(data[:n])
		one := h.Sum(nil)

		h = NewTest()
		h.Write(data[:n/2])
		h.Write(data[n/2 : n])
		if two := h.Sum(nil); !bytes.Equal(one, two) {
			t.Fatalf("длина %d: %x != %x", n, one, two)
		}
		if prev, ok := seen[string(one)]; ok {
			t.Fatalf("длины %d и %d дали одинаковый хэш", prev, n)
		}
		seen[string(one)] = n
	}
}

func TestSumDoesNotMutate(t *testing.T) {
	h := NewTest()
	h.Write([]byte("первая часть"))
	first := h.Sum(nil)
	if second := h.Sum(nil); !bytes.Equal(first, second) {
		t.Fatalf("повторный Sum дал другой результат")
	}
	h.Write([]byte(" и вторая"))
	combined := h.Sum(nil)

	ref := NewTest()
	ref.Write([]byte("первая часть и вторая"))
	if want := ref.Sum(nil); !bytes.Equal(combined, want) {
		t.Fatalf("после Sum состояние испорчено")
	}
}

func TestReset(t *testing.T) {
	msg := revHex(t, m1Std)
	want := revHex(t, h1Std)
	h := NewTest()
	h.Write([]byte("мусор"))
	h.Reset()
	h.Write(msg)
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("после Reset = %x", got)
	}
}

// Наборы подстановок и начальное значение — параметры функции: результат
// обязан от них зависеть.
func TestParametersMatter(t *testing.T) {
	msg := []byte("сообщение")

	test := NewTest()
	test.Write(msg)
	cryptoPro := NewCryptoPro()
	cryptoPro.Write(msg)
	if bytes.Equal(test.Sum(nil), cryptoPro.Sum(nil)) {
		t.Fatal("разные наборы подстановок дали одинаковый хэш")
	}

	h0 := make([]byte, Size)
	h0[0] = 1
	other, err := New(gost28147.ParamHashCryptoPro(), h0)
	if err != nil {
		t.Fatal(err)
	}
	other.Write(msg)
	if bytes.Equal(other.Sum(nil), cryptoPro.Sum(nil)) {
		t.Fatal("начальное значение не влияет на результат")
	}

	if got := Sum256(msg); !bytes.Equal(got[:], cryptoPro.Sum(nil)) {
		t.Fatal("Sum256 расходится с NewCryptoPro")
	}
}

func TestSizes(t *testing.T) {
	h := NewCryptoPro()
	if h.Size() != Size {
		t.Errorf("Size() = %d", h.Size())
	}
	if h.BlockSize() != BlockSize {
		t.Errorf("BlockSize() = %d", h.BlockSize())
	}
}

func TestNewRejectsBadSBox(t *testing.T) {
	var broken gost28147.SBox
	if _, err := New(&broken, nil); err == nil {
		t.Fatal("нулевой набор подстановок принят")
	}
	if _, err := New(nil, nil); err == nil {
		t.Fatal("nil-набор принят")
	}
}

func benchmarkHash(b *testing.B, h hash.Hash, n int) {
	buf := make([]byte, n)
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(nil)
	}
}

func BenchmarkHash8K(b *testing.B) { benchmarkHash(b, NewCryptoPro(), 8192) }
