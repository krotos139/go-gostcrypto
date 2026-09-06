// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3410

import (
	"math/big"
	"math/rand"
	"testing"
)

// Собственная арифметика поля должна совпадать с math/big на всех кривых.
// Контрольные примеры подписи проверяют её лишь косвенно: они пройдут и
// при ошибке, которая проявляется на редких значениях. Здесь операции
// сверяются напрямую, включая крайние случаи и случайные входы.

func fieldsUnderTest() map[string]*field {
	out := map[string]*field{}
	for _, c := range AllCurves() {
		out[c.Name()] = c.f
	}
	return out
}

// roundTrip проверяет, что перевод в форму Монтгомери и обратно
// сохраняет значение.
func TestMontgomeryRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for name, f := range fieldsUnderTest() {
		t.Run(name, func(t *testing.T) {
			values := edgeValues(f)
			for i := 0; i < 200; i++ {
				values = append(values, randBelow(rng, f.pBig))
			}
			for _, v := range values {
				var m fe
				f.toMont(&m, v)
				if got := f.fromMont(&m); got.Cmp(v) != 0 {
					t.Fatalf("значение %x не восстановилось: %x", v, got)
				}
			}
		})
	}
}

func edgeValues(f *field) []*big.Int {
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(f.pBig, one)
	pm2 := new(big.Int).Sub(pm1, one)
	half := new(big.Int).Rsh(f.pBig, 1)
	return []*big.Int{
		big.NewInt(0), one, big.NewInt(2), half, pm2, pm1,
	}
}

func randBelow(rng *rand.Rand, max *big.Int) *big.Int {
	n := (max.BitLen() + 7) / 8
	b := make([]byte, n)
	for {
		rng.Read(b)
		v := new(big.Int).SetBytes(b)
		if v.Cmp(max) < 0 {
			return v
		}
	}
}

func TestFieldOpsMatchBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for name, f := range fieldsUnderTest() {
		t.Run(name, func(t *testing.T) {
			var values []*big.Int
			values = append(values, edgeValues(f)...)
			for i := 0; i < 150; i++ {
				values = append(values, randBelow(rng, f.pBig))
			}

			check := func(op string, x, y *big.Int, got *fe, want *big.Int) {
				t.Helper()
				want = new(big.Int).Mod(want, f.pBig)
				if g := f.fromMont(got); g.Cmp(want) != 0 {
					t.Fatalf("%s(%x, %x):\n  получено %x\n  ожидалось %x", op, x, y, g, want)
				}
			}

			for i, x := range values {
				// Пары берём со сдвигом, чтобы покрыть и крайние
				// значения вместе со случайными.
				y := values[(i*7+3)%len(values)]

				var xm, ym, z fe
				f.toMont(&xm, x)
				f.toMont(&ym, y)

				f.add(&z, &xm, &ym)
				check("add", x, y, &z, new(big.Int).Add(x, y))

				f.sub(&z, &xm, &ym)
				check("sub", x, y, &z, new(big.Int).Sub(x, y))

				f.mul(&z, &xm, &ym)
				check("mul", x, y, &z, new(big.Int).Mul(x, y))

				f.sqr(&z, &xm)
				check("sqr", x, x, &z, new(big.Int).Mul(x, x))

				f.dbl(&z, &xm)
				check("dbl", x, x, &z, new(big.Int).Lsh(x, 1))

				var inv, prod fe
				f.inv(&inv, &xm)
				if x.Sign() == 0 {
					// 0^(p-2) = 0
					if !f.isZero(&inv) {
						t.Fatalf("inv(0) != 0")
					}
				} else {
					f.mul(&prod, &xm, &inv)
					if !f.equal(&prod, &f.one) {
						t.Fatalf("x * x^-1 != 1 для %x", x)
					}
				}
			}
		})
	}
}

// Результат операции всегда должен быть меньше модуля: иначе где-то
// пропущено условное вычитание.
func TestFieldResultsReduced(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for name, f := range fieldsUnderTest() {
		t.Run(name, func(t *testing.T) {
			pm1 := new(big.Int).Sub(f.pBig, big.NewInt(1))
			var big1, big2 fe
			f.toMont(&big1, pm1)
			f.toMont(&big2, pm1)

			ops := []struct {
				name string
				fn   func(z, x, y *fe)
			}{
				{"add", f.add},
				{"sub", f.sub},
				{"mul", f.mul},
			}
			for _, op := range ops {
				var z fe
				op.fn(&z, &big1, &big2)
				if v := limbsToBig(&z, f.n); v.Cmp(f.pBig) >= 0 {
					t.Fatalf("%s на (p-1, p-1) дал непривёдённое значение", op.name)
				}
				for i := 0; i < 100; i++ {
					var xm, ym fe
					f.toMont(&xm, randBelow(rng, f.pBig))
					f.toMont(&ym, randBelow(rng, f.pBig))
					op.fn(&z, &xm, &ym)
					if v := limbsToBig(&z, f.n); v.Cmp(f.pBig) >= 0 {
						t.Fatalf("%s дал непривёдённое значение", op.name)
					}
				}
			}
		})
	}
}

// Константы поля должны быть согласованы между собой.
func TestFieldConstants(t *testing.T) {
	for name, f := range fieldsUnderTest() {
		t.Run(name, func(t *testing.T) {
			if f.n != (f.pBig.BitLen()+63)/64 {
				t.Fatalf("число слов %d не соответствует модулю", f.n)
			}
			// n0 = -p^-1 mod 2^64
			if got := f.p[0] * f.n0; got != ^uint64(0) {
				// p[0] * (-p^-1) = -1 = 0xFFFF... по модулю 2^64
				t.Fatalf("p[0]*n0 = %016x, ожидалось ffffffffffffffff", got)
			}
			// one — это R mod p
			r := new(big.Int).Lsh(big.NewInt(1), uint(64*f.n))
			r.Mod(r, f.pBig)
			if got := limbsToBig(&f.one, f.n); got.Cmp(r) != 0 {
				t.Fatalf("one = %x, ожидалось %x", got, r)
			}
			// fromMont(one) должно давать единицу
			if got := f.fromMont(&f.one); got.Cmp(big.NewInt(1)) != 0 {
				t.Fatalf("fromMont(one) = %x", got)
			}
		})
	}
}

// Аргументы операций могут совпадать с результатом.
func TestFieldAliasing(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for name, f := range fieldsUnderTest() {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				x := randBelow(rng, f.pBig)
				y := randBelow(rng, f.pBig)
				var xm, ym, want fe
				f.toMont(&xm, x)
				f.toMont(&ym, y)

				f.mul(&want, &xm, &ym)
				got := xm
				f.mul(&got, &got, &ym)
				if !f.equal(&got, &want) {
					t.Fatal("mul с совпадающими dst и x дал другой результат")
				}
				got = ym
				f.mul(&got, &xm, &got)
				if !f.equal(&got, &want) {
					t.Fatal("mul с совпадающими dst и y дал другой результат")
				}

				f.add(&want, &xm, &ym)
				got = xm
				f.add(&got, &got, &ym)
				if !f.equal(&got, &want) {
					t.Fatal("add с совпадающими dst и x дал другой результат")
				}

				f.sub(&want, &xm, &ym)
				got = xm
				f.sub(&got, &got, &ym)
				if !f.equal(&got, &want) {
					t.Fatal("sub с совпадающими dst и x дал другой результат")
				}
			}
		})
	}
}

// Полные формулы обязаны давать верный результат во всех случаях, где
// обычные требуют отдельного разбора: удвоение через сложение, сложение с
// противоположной точкой, сложение с нейтральным элементом.
func TestCompleteFormulas(t *testing.T) {
	for _, c := range AllCurves() {
		t.Run(c.Name(), func(t *testing.T) {
			gx, gy := c.Generator()
			var g, dbl, sum, neutral point
			c.fromAffine(&g, gx, gy)
			c.setNeutral(&neutral)

			// Удвоение и сложение точки с собой.
			c.doublePoint(&dbl, &g)
			c.addPoint(&sum, &g, &g)
			x1, y1 := c.toAffine(&dbl)
			x2, y2 := c.toAffine(&sum)
			if x1 == nil || x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
				t.Fatal("удвоение и сложение точки с собой разошлись")
			}
			if !c.IsOnCurve(x1, y1) {
				t.Fatal("удвоенная точка не лежит на кривой")
			}

			// P + (-P) = O.
			negY := new(big.Int).Sub(c.P(), gy)
			var neg, zero point
			c.fromAffine(&neg, gx, negY)
			c.addPoint(&zero, &g, &neg)
			if !c.isInfinity(&zero) {
				t.Fatal("P + (-P) не дало нейтральный элемент")
			}

			// P + O = P и O + P = P.
			var r point
			c.addPoint(&r, &g, &neutral)
			rx, ry := c.toAffine(&r)
			if rx == nil || rx.Cmp(gx) != 0 || ry.Cmp(gy) != 0 {
				t.Fatal("P + O != P")
			}
			c.addPoint(&r, &neutral, &g)
			rx, ry = c.toAffine(&r)
			if rx == nil || rx.Cmp(gx) != 0 || ry.Cmp(gy) != 0 {
				t.Fatal("O + P != P")
			}

			// O + O = O и 2O = O.
			c.addPoint(&r, &neutral, &neutral)
			if !c.isInfinity(&r) {
				t.Fatal("O + O != O")
			}
			c.doublePoint(&r, &neutral)
			if !c.isInfinity(&r) {
				t.Fatal("2O != O")
			}
		})
	}
}

// Умножение на скаляр должно согласовываться с повторным сложением, а
// гребёнка — с оконным методом.
func TestScalarMultConsistency(t *testing.T) {
	for _, c := range AllCurves() {
		t.Run(c.Name(), func(t *testing.T) {
			gx, gy := c.Generator()
			accX, accY := gx, gy
			for k := 2; k <= 20; k++ {
				accX, accY = c.Add(accX, accY, gx, gy)
				bx, by := c.ScalarBaseMult(big.NewInt(int64(k)))
				wx, wy := c.ScalarMult(gx, gy, big.NewInt(int64(k)))
				if bx == nil || bx.Cmp(accX) != 0 || by.Cmp(accY) != 0 {
					t.Fatalf("k=%d: гребёнка разошлась со сложением", k)
				}
				if wx.Cmp(accX) != 0 || wy.Cmp(accY) != 0 {
					t.Fatalf("k=%d: оконный метод разошёлся со сложением", k)
				}
			}
			// q*P должно давать нейтральный элемент.
			if x, _ := c.ScalarBaseMult(c.Q()); x != nil {
				t.Fatal("q*P не дало нейтральный элемент")
			}
		})
	}
}

// Образующая точка обязана лежать в подгруппе простого порядка на любой
// кривой, а проверка должна отличать кофакторные кривые от остальных.
func TestInSubgroup(t *testing.T) {
	seenCofactor := map[int64]bool{}
	for _, c := range AllCurves() {
		gx, gy := c.Generator()
		if !c.InSubgroup(gx, gy) {
			t.Errorf("%s: образующая не в подгруппе", c.Name())
		}
		seenCofactor[c.Cofactor().Int64()] = true
	}
	if !seenCofactor[1] || !seenCofactor[4] {
		t.Fatal("проверка неполна: нет кривых обоих видов кофактора")
	}
}

func BenchmarkFieldMul(b *testing.B) {
	f := TC26ParamSet256B().f
	var x, y, z fe
	f.toMont(&x, big.NewInt(0x123456789abcdef))
	f.toMont(&y, big.NewInt(0xfedcba987654321))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.mul(&z, &x, &y)
	}
}

// --- механизмы защиты от утечек по времени ---------------------------------

// condMove должна копировать при маске из единиц и не трогать назначение
// при нулевой маске. Промежуточных значений маска принимать не должна:
// они означали бы ошибку в вычислении признака.
func TestCondMove(t *testing.T) {
	f := TC26ParamSet256B().f
	var a, b, want fe
	f.toMont(&a, big.NewInt(0x1111))
	f.toMont(&b, big.NewInt(0x2222))

	want = a
	got := a
	f.condMove(&got, &b, 0)
	if !f.equal(&got, &want) {
		t.Fatal("нулевая маска изменила назначение")
	}
	f.condMove(&got, &b, ^uint64(0))
	if !f.equal(&got, &b) {
		t.Fatal("единичная маска не скопировала источник")
	}
}

// selectPoint обязана возвращать ровно ту запись, номер которой ей
// передан, просматривая при этом всю таблицу. Проверяем на всех индексах
// обеих используемых таблиц.
func TestSelectPointCorrect(t *testing.T) {
	c := TC26ParamSet256B()
	gx, gy := c.Generator()

	sizes := []int{1 << scalarWindow, 1 << combWidth}
	for _, n := range sizes {
		tbl := make([]point, n)
		c.setNeutral(&tbl[0])
		c.fromAffine(&tbl[1], gx, gy)
		for i := 2; i < n; i++ {
			c.addPoint(&tbl[i], &tbl[i-1], &tbl[1])
		}
		var sel point
		for i := 0; i < n; i++ {
			c.selectPoint(&sel, tbl, i)
			if !c.f.equal(&sel.x, &tbl[i].x) ||
				!c.f.equal(&sel.y, &tbl[i].y) ||
				!c.f.equal(&sel.z, &tbl[i].z) {
				t.Fatalf("таблица на %d записей: выбор номера %d вернул не ту точку", n, i)
			}
		}
	}
}

// Подпись должна быть верна при любом k, включая крайние значения: при
// постоянном времени работы особых случаев быть не должно.
func TestSignExtremeScalars(t *testing.T) {
	c := TC26ParamSet256B()
	priv, err := NewPrivateKey(c, big.NewInt(0x123456789abcdef))
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(0x2222)

	qm1 := new(big.Int).Sub(c.Q(), big.NewInt(1))
	scalars := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		qm1,
		new(big.Int).Rsh(c.Q(), 1),
		new(big.Int).Sub(c.Q(), big.NewInt(2)),
	}
	digest := digestForE(t, c, e)

	for _, k := range scalars {
		r, s, ok := signWithK(priv, e, k)
		if !ok {
			t.Fatalf("k=%x: подпись не сформирована", k)
		}
		if !VerifyDigestRS(&priv.PublicKey, digest, r, s) {
			t.Fatalf("k=%x: подпись не прошла проверку", k)
		}
	}
}

func BenchmarkDoublePoint(b *testing.B) {
	c := TC26ParamSet256B()
	gx, gy := c.Generator()
	var p point
	c.fromAffine(&p, gx, gy)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.doublePoint(&p, &p)
	}
}

func BenchmarkAddPoint(b *testing.B) {
	c := TC26ParamSet256B()
	gx, gy := c.Generator()
	var p, q point
	c.fromAffine(&p, gx, gy)
	c.doublePoint(&q, &p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.addPoint(&p, &p, &q)
	}
}

func BenchmarkSelectPointComb(b *testing.B) {
	c := TC26ParamSet256B()
	tbl := c.combTable()
	var sel point
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.selectPoint(&sel, tbl, i&(len(tbl)-1))
	}
}

func BenchmarkFieldInv(b *testing.B) {
	c := TC26ParamSet256B()
	var x, z fe
	c.f.toMont(&x, big.NewInt(0x123456789abcdef))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.f.inv(&z, &x)
	}
}
