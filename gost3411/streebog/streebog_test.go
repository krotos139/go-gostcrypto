// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package streebog

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math/rand"
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

// revHex разбирает шестнадцатеричную запись стандарта и разворачивает её в
// порядок потока. И сообщения, и хэш-коды в ГОСТ Р 34.11-2012 и RFC 6986
// напечатаны старшим разрядом влево, то есть задом наперёд относительно
// того, как байты идут в файле или в сети.
func revHex(t testing.TB, s string) []byte {
	t.Helper()
	b := mustHex(t, s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// Контрольные примеры из ГОСТ Р 34.11-2012, раздел 10 (RFC 6986, раздел 10),
// в исходной записи стандарта.
const (
	m1Std = "32313039383736353433323130393837" +
		"36353433323130393837363534333231" +
		"30393837363534333231303938373635" +
		"343332313039383736353433323130"

	m1H512Std = "486f64c1917879417fef082b3381a4e2" +
		"11c324f074654c38823a7b76f830ad00" +
		"fa1fbae42b1285c0352f227524bc9ab1" +
		"6254288dd6863dccd5b9f54a1ad0541b"

	m1H256Std = "00557be5e584fd52a449b16b0251d05d" +
		"27f94ab76cbaa6da890b59d8ef1e159d"

	m2Std = "fbe2e5f0eee3c820fbeafaebef20fffb" +
		"f0e1e0f0f520e0ed20e8ece0ebe5f0f2" +
		"f120fff0eeec20f120faf2fee5e2202c" +
		"e8f6f3ede220e8e6eee1e8f0f2d1202c" +
		"e8f0f2e5e220e5d1"

	m2H512Std = "28fbc9bada033b1460642bdcddb90c3f" +
		"b3e56c497ccd0f62b8a2ad4935e85f03" +
		"7613966de4ee00531ae60f3b5a47f8da" +
		"e06915d5f2f194996fcabf2622e6881e"

	m2H256Std = "508f7e553c06501d749a66fc28c6cac0" +
		"b005746d97537fa85d9e40904efed29d"
)

// Первое, что нужно зафиксировать: сообщение M1 из стандарта — это обычная
// ASCII-строка, напечатанная задом наперёд. Если этот тест падает, значит
// соглашение о порядке байт понято неверно, и все остальные тесты
// бессмысленны.
func TestStandardHexIsReversed(t *testing.T) {
	want := "012345678901234567890123456789012345678901234567890123456789012"
	if got := string(revHex(t, m1Std)); got != want {
		t.Fatalf("M1 в потоковом порядке = %q, ожидалось %q", got, want)
	}
	if len(want) != 63 {
		t.Fatalf("|M1| = %d байт, ожидалось 63", len(want))
	}
}

// ГОСТ Р 34.11-2012, 10.1 и 10.2 (RFC 6986).
func TestKAT(t *testing.T) {
	cases := []struct {
		name           string
		msg            string
		h512, h256     string
		expectedMsgLen int
	}{
		{"пример 1", m1Std, m1H512Std, m1H256Std, 63},
		{"пример 2", m2Std, m2H512Std, m2H256Std, 72},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := revHex(t, c.msg)
			if len(msg) != c.expectedMsgLen {
				t.Fatalf("длина сообщения %d, ожидалось %d", len(msg), c.expectedMsgLen)
			}

			h := New512()
			h.Write(msg)
			if got, want := h.Sum(nil), revHex(t, c.h512); !bytes.Equal(got, want) {
				t.Errorf("H512 = %x\n    ожидалось %x", got, want)
			}

			h = New256()
			h.Write(msg)
			if got, want := h.Sum(nil), revHex(t, c.h256); !bytes.Equal(got, want) {
				t.Errorf("H256 = %x\n    ожидалось %x", got, want)
			}

			s512 := Sum512(msg)
			if got, want := s512[:], revHex(t, c.h512); !bytes.Equal(got, want) {
				t.Errorf("Sum512 = %x, ожидалось %x", got, want)
			}
			s256 := Sum256(msg)
			if got, want := s256[:], revHex(t, c.h256); !bytes.Equal(got, want) {
				t.Errorf("Sum256 = %x, ожидалось %x", got, want)
			}
		})
	}
}

// 256-битный вариант — не усечение 512-битного: у него другое начальное
// значение, поэтому результаты не должны совпадать ни одним концом.
func TestSizesAreIndependent(t *testing.T) {
	msg := revHex(t, m1Std)
	full := Sum512(msg)
	short := Sum256(msg)
	if bytes.Equal(short[:], full[:Size256]) || bytes.Equal(short[:], full[Size-Size256:]) {
		t.Fatal("256-битный хэш совпал с частью 512-битного — начальные значения перепутаны")
	}
}

// --- эталонная реализация преобразований ----------------------------------

// Таблицы lpsTable выводятся из pi, tau и матрицы A нетривиально: свёртка
// опирается на то, что после перестановки P байт номер j слова k попадает в
// байт номер k слова j. Ошибка в этой выкладке дала бы неверный хэш на
// любом входе, поэтому свёртка сверяется с прямой реализацией по формулам
// раздела 7 стандарта.

func refS(a *[64]byte) {
	for i, v := range a {
		a[i] = pi[v]
	}
}

func refP(a *[64]byte) {
	var r [64]byte
	for i := 0; i < 64; i++ {
		r[i] = a[tau[i]]
	}
	*a = r
}

func refL(a *[64]byte) {
	for j := 0; j < 8; j++ {
		w := binary.LittleEndian.Uint64(a[8*j:])
		binary.LittleEndian.PutUint64(a[8*j:], lRef(w))
	}
}

func refLPS(in state) state {
	var a [64]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(a[8*i:], in[i])
	}
	refS(&a)
	refP(&a)
	refL(&a)
	var out state
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint64(a[8*i:])
	}
	return out
}

func TestLPSMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 2000; iter++ {
		var in state
		for i := range in {
			in[i] = rng.Uint64()
		}
		var got state
		lps(&got, &in)
		if want := refLPS(in); got != want {
			t.Fatalf("LPS(%016x) = %016x\n    эталон %016x", in, got, want)
		}
	}
	// Крайние случаи: нулевой и единичный векторы.
	for _, in := range []state{{}, {^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0),
		^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}} {
		var got state
		lps(&got, &in)
		if want := refLPS(in); got != want {
			t.Fatalf("LPS(%016x) = %016x, эталон %016x", in, got, want)
		}
	}
}

// lps обязана работать при совпадающих dst и src.
func TestLPSInPlace(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for iter := 0; iter < 200; iter++ {
		var in state
		for i := range in {
			in[i] = rng.Uint64()
		}
		var want state
		lps(&want, &in)
		got := in
		lps(&got, &got)
		if got != want {
			t.Fatalf("lps на месте = %016x, ожидалось %016x", got, want)
		}
	}
}

// Константы должны разобраться ровно так, как напечатаны: слово 0 — младшие
// разряды, то есть последние восемь байт записи.
func TestConstantsParsed(t *testing.T) {
	if c[0][7] != 0xb1085bda1ecadae9 {
		t.Errorf("C[1], старшее слово = %016x, ожидалось b1085bda1ecadae9", c[0][7])
	}
	if c[0][0] != 0xdd806559f2a64507 {
		t.Errorf("C[1], младшее слово = %016x, ожидалось dd806559f2a64507", c[0][0])
	}
	if c[11][7] != 0x378ee767f11631ba {
		t.Errorf("C[12], старшее слово = %016x", c[11][7])
	}
	if c[11][0] != 0x48bc924af11bd720 {
		t.Errorf("C[12], младшее слово = %016x", c[11][0])
	}
}

func TestPiIsBijection(t *testing.T) {
	var seen [256]bool
	for _, v := range pi {
		if seen[v] {
			t.Fatalf("pi не биективна: %d встречается дважды", v)
		}
		seen[v] = true
	}
}

func TestTauIsPermutation(t *testing.T) {
	var seen [64]bool
	for _, v := range tau {
		if seen[v] {
			t.Fatalf("tau не перестановка: %d встречается дважды", v)
		}
		seen[v] = true
	}
}

// --- потоковый интерфейс --------------------------------------------------

// Результат не должен зависеть от того, как данные нарезаны между вызовами
// Write. Особое внимание — границам блока: 63, 64, 65 байт.
func TestChunkedWrites(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	msg := make([]byte, 500)
	rng.Read(msg)

	for _, size := range []int{Size, Size256} {
		newHash := New512
		if size == Size256 {
			newHash = New256
		}
		h := newHash()
		h.Write(msg)
		want := h.Sum(nil)

		for _, chunk := range []int{1, 2, 3, 7, 31, 63, 64, 65, 100, 127, 128, 129, 500} {
			h := newHash()
			for off := 0; off < len(msg); off += chunk {
				h.Write(msg[off:min(off+chunk, len(msg))])
			}
			if got := h.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("размер %d, куски по %d: %x, ожидалось %x", size, chunk, got, want)
			}
		}
	}
}

// Длины вокруг границ блока обрабатываются особым образом: сообщение,
// кратное 64 байтам, всё равно получает завершающий блок дополнения.
func TestLengthsAroundBlockBoundary(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	data := make([]byte, 300)
	rng.Read(data)

	for n := 0; n <= 200; n++ {
		h := New512()
		h.Write(data[:n])
		one := h.Sum(nil)

		// То же самое, но двумя записями по половине.
		h = New512()
		h.Write(data[:n/2])
		h.Write(data[n/2 : n])
		two := h.Sum(nil)

		if !bytes.Equal(one, two) {
			t.Fatalf("длина %d: %x != %x", n, one, two)
		}
		if got := Sum512(data[:n]); !bytes.Equal(got[:], one) {
			t.Fatalf("длина %d: Sum512 = %x, ожидалось %x", n, got, one)
		}
	}
}

// Sum не должен изменять состояние: после него можно продолжать писать.
func TestSumDoesNotMutate(t *testing.T) {
	h := New512()
	h.Write([]byte("первая часть"))
	first := h.Sum(nil)
	second := h.Sum(nil)
	if !bytes.Equal(first, second) {
		t.Fatalf("повторный Sum дал другой результат: %x != %x", first, second)
	}

	h.Write([]byte(" и вторая"))
	combined := h.Sum(nil)

	ref := New512()
	ref.Write([]byte("первая часть и вторая"))
	if want := ref.Sum(nil); !bytes.Equal(combined, want) {
		t.Fatalf("после Sum состояние испорчено: %x, ожидалось %x", combined, want)
	}
}

// Sum должен дописывать к переданному срезу, а не затирать его.
func TestSumAppends(t *testing.T) {
	h := New256()
	h.Write([]byte("данные"))
	prefix := []byte("префикс")
	out := h.Sum(prefix)
	if !bytes.HasPrefix(out, prefix) {
		t.Fatalf("Sum затёр префикс: %q", out)
	}
	if len(out) != len(prefix)+Size256 {
		t.Fatalf("длина результата %d, ожидалось %d", len(out), len(prefix)+Size256)
	}
}

func TestReset(t *testing.T) {
	msg := revHex(t, m1Std)
	want := revHex(t, m1H512Std)

	h := New512()
	h.Write([]byte("мусор, который надо забыть"))
	h.Reset()
	h.Write(msg)
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("после Reset = %x, ожидалось %x", got, want)
	}
}

func TestSizeAndBlockSize(t *testing.T) {
	if got := New512().Size(); got != Size {
		t.Errorf("New512().Size() = %d, ожидалось %d", got, Size)
	}
	if got := New256().Size(); got != Size256 {
		t.Errorf("New256().Size() = %d, ожидалось %d", got, Size256)
	}
	if got := New512().BlockSize(); got != BlockSize {
		t.Errorf("BlockSize() = %d, ожидалось %d", got, BlockSize)
	}
}

// --- сериализация состояния -----------------------------------------------

func TestMarshalRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	data := make([]byte, 200)
	rng.Read(data)

	for _, newHash := range []func() hash.Hash{New512, New256} {
		for _, split := range []int{0, 1, 63, 64, 65, 130} {
			h := newHash()
			h.Write(data[:split])

			snapshot, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			restored := newHash()
			if err := restored.(encoding.BinaryUnmarshaler).UnmarshalBinary(snapshot); err != nil {
				t.Fatalf("split=%d: %v", split, err)
			}

			h.Write(data[split:])
			restored.Write(data[split:])
			if !bytes.Equal(h.Sum(nil), restored.Sum(nil)) {
				t.Fatalf("split=%d: восстановленное состояние даёт другой хэш", split)
			}
		}
	}
}

// Снимок с 256-битного хэша не должен приниматься 512-битным и наоборот.
func TestMarshalRejectsWrongSize(t *testing.T) {
	h256 := New256()
	snapshot, err := h256.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := New512().(encoding.BinaryUnmarshaler).UnmarshalBinary(snapshot); err != ErrState {
		t.Fatalf("снимок 256 принят 512-битным хэшем: err = %v", err)
	}
}

func TestMarshalRejectsGarbage(t *testing.T) {
	h := New512()
	good, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	cases := [][]byte{
		nil,
		good[:len(good)-1],
		append(append([]byte(nil), good...), 0),
	}
	bad := append([]byte(nil), good...)
	bad[0] ^= 0xff
	cases = append(cases, bad)

	tooLarge := append([]byte(nil), good...)
	tooLarge[len(tooLarge)-1] = BlockSize
	cases = append(cases, tooLarge)

	for i, b := range cases {
		if err := New512().(encoding.BinaryUnmarshaler).UnmarshalBinary(b); err != ErrState {
			t.Errorf("случай %d: err = %v, ожидалось ErrState", i, err)
		}
	}
}

// --- бенчмарки ------------------------------------------------------------

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

func BenchmarkHash512_8K(b *testing.B) { benchmarkHash(b, New512(), 8192) }
func BenchmarkHash256_8K(b *testing.B) { benchmarkHash(b, New256(), 8192) }
func BenchmarkHash512_64(b *testing.B) { benchmarkHash(b, New512(), 64) }
