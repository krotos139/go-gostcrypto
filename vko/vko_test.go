// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package vko

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3410"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// leInt читает октетную строку как число от младшего байта к старшему.
func leInt(t testing.TB, s string) *big.Int {
	t.Helper()
	return UKMFromBytes(mustHex(t, s))
}

// Контрольные примеры из Р 50.1.113-2016, приложение А
// (RFC 7836, приложение B, примеры 7 и 8). Кривая —
// id-tc26-gost-3410-12-512-paramSetA.
const (
	ukmHex = "1d80603c8544c727"

	dAHex = "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8" +
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"
	qAHex = "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5" +
		"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7" +
		"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38" +
		"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a"

	dBHex = "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b" +
		"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"
	qBHex = "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e" +
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651" +
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b" +
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"

	wantKEK256 = "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"

	wantKEK512 = "79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa" +
		"7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf"
)

// keyPair восстанавливает пару ключей из записи стандарта. И ключ подписи,
// и координаты ключа проверки записаны от младшего байта к старшему.
func keyPair(t testing.TB, dHex, qHex string) (*gost3410.PrivateKey, *gost3410.PublicKey) {
	t.Helper()
	c := gost3410.TC26ParamSet512A()
	size := c.Size()

	priv, err := gost3410.NewPrivateKey(c, leInt(t, dHex))
	if err != nil {
		t.Fatalf("ключ подписи: %v", err)
	}
	raw := mustHex(t, qHex)
	pub, err := gost3410.NewPublicKey(c,
		UKMFromBytes(raw[:size]), UKMFromBytes(raw[size:]))
	if err != nil {
		t.Fatalf("ключ проверки: %v", err)
	}
	return priv, pub
}

// Прежде чем сверять KEK, надо убедиться, что кодировка ключей понята
// верно: вычисленный из d ключ проверки обязан совпасть с записанным.
func TestKeyEncoding(t *testing.T) {
	privA, pubA := keyPair(t, dAHex, qAHex)
	if privA.X.Cmp(pubA.X) != 0 || privA.Y.Cmp(pubA.Y) != 0 {
		t.Fatalf("d_A*P не совпал с Q_A:\n  вычислено (%x, %x)\n  записано  (%x, %x)",
			privA.X, privA.Y, pubA.X, pubA.Y)
	}
	privB, pubB := keyPair(t, dBHex, qBHex)
	if privB.X.Cmp(pubB.X) != 0 || privB.Y.Cmp(pubB.Y) != 0 {
		t.Fatal("d_B*P не совпал с Q_B")
	}
}

// RFC 7836, приложение B, примеры 7 и 8.
func TestKAT(t *testing.T) {
	privA, pubA := keyPair(t, dAHex, qAHex)
	privB, pubB := keyPair(t, dBHex, qBHex)
	ukm := leInt(t, ukmHex)

	t.Run("KEK256", func(t *testing.T) {
		want := mustHex(t, wantKEK256)
		got, err := KEK256(privA, pubB, ukm)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("сторона A: %x\n  ожидалось %x", got, want)
		}
		// Согласование: вторая сторона должна получить тот же ключ.
		other, err := KEK256(privB, pubA, ukm)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(other, want) {
			t.Fatalf("сторона B: %x", other)
		}
	})

	t.Run("KEK512", func(t *testing.T) {
		want := mustHex(t, wantKEK512)
		got, err := KEK512(privA, pubB, ukm)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("сторона A: %x\n  ожидалось %x", got, want)
		}
		other, err := KEK512(privB, pubA, ukm)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(other, want) {
			t.Fatalf("сторона B: %x", other)
		}
	})
}

// UKM читается от младшего байта к старшему. Если бы порядок был обратный,
// контрольный пример не сошёлся бы — этот тест фиксирует соглашение явно.
func TestUKMIsLittleEndian(t *testing.T) {
	got := UKMFromBytes([]byte{0x01, 0x02, 0x03})
	if want := big.NewInt(0x030201); got.Cmp(want) != 0 {
		t.Fatalf("UKMFromBytes = %x, ожидалось %x", got, want)
	}

	privA, _ := keyPair(t, dAHex, qAHex)
	_, pubB := keyPair(t, dBHex, qBHex)

	raw := mustHex(t, ukmHex)
	be := new(big.Int).SetBytes(raw) // тот же UKM в обратном порядке
	wrong, err := KEK256(privA, pubB, be)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrong, mustHex(t, wantKEK256)) {
		t.Fatal("порядок байт UKM не влияет на результат — тест бесполезен")
	}
}

// Согласование должно работать на всех кривых, включая те, у которых
// кофактор равен четырём.
func TestAgreementOnAllCurves(t *testing.T) {
	for _, c := range gost3410.AllCurves() {
		t.Run(c.Name(), func(t *testing.T) {
			a, err := gost3410.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			b, err := gost3410.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ukm := big.NewInt(0x1d80603c8544c727)

			ka, err := KEK256(a, &b.PublicKey, ukm)
			if err != nil {
				t.Fatal(err)
			}
			kb, err := KEK256(b, &a.PublicKey, ukm)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ka, kb) {
				t.Fatal("стороны получили разные ключи")
			}

			// Другой UKM обязан дать другой ключ.
			other, err := KEK256(a, &b.PublicKey, big.NewInt(2))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(ka, other) {
				t.Fatal("UKM не влияет на результат")
			}
		})
	}
}

// Множитель m/q отличает ВКО-2012 от ВКО-2001 (RFC 4357, п. 5.2). На
// кривых с кофактором 1 формулы совпадают, на кривых с кофактором 4 —
// нет. Официальных векторов для второго случая нет, поэтому расхождение
// фиксируется здесь явно.
func TestCofactorMatters(t *testing.T) {
	cofactorOne := 0
	cofactorFour := 0

	for _, c := range gost3410.AllCurves() {
		cof := new(big.Int).Div(c.M(), c.Q())
		switch cof.Int64() {
		case 1:
			cofactorOne++
		case 4:
			cofactorFour++
		default:
			t.Errorf("%s: неожиданный кофактор %s", c.Name(), cof)
		}

		a, err := gost3410.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b, err := gost3410.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ukm := big.NewInt(12345)

		withCofactor, _, err := SharedPoint(a, &b.PublicKey, ukm)
		if err != nil {
			t.Fatal(err)
		}
		// То же самое без множителя m/q — формула версии 2001 года.
		coef := new(big.Int).Mul(ukm, a.D)
		coef.Mod(coef, c.Q())
		without, _ := c.ScalarMult(b.X, b.Y, coef)

		same := withCofactor.Cmp(without) == 0
		if cof.Int64() == 1 && !same {
			t.Errorf("%s: кофактор 1, но результаты разошлись", c.Name())
		}
		if cof.Int64() == 4 && same {
			t.Errorf("%s: кофактор 4, но результаты совпали", c.Name())
		}
	}

	if cofactorOne == 0 || cofactorFour == 0 {
		t.Fatalf("проверка неполна: кривых с кофактором 1 — %d, с кофактором 4 — %d",
			cofactorOne, cofactorFour)
	}
}

func TestErrors(t *testing.T) {
	a, err := gost3410.GenerateKey(gost3410.TestParamSet256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := gost3410.GenerateKey(gost3410.TC26ParamSet512A(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := KEK256(a, &b.PublicKey, big.NewInt(1)); err != ErrCurveMismatch {
		t.Errorf("разные кривые: err = %v", err)
	}
	for _, ukm := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if _, err := KEK256(a, &a.PublicKey, ukm); err != ErrUKM {
			t.Errorf("UKM = %v: err = %v", ukm, err)
		}
	}
}

func BenchmarkKEK256(b *testing.B) {
	c := gost3410.TC26ParamSet256B()
	priv, _ := gost3410.GenerateKey(c, rand.Reader)
	peer, _ := gost3410.GenerateKey(c, rand.Reader)
	ukm := big.NewInt(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := KEK256(priv, &peer.PublicKey, ukm); err != nil {
			b.Fatal(err)
		}
	}
}
