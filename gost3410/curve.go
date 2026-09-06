// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3410

import (
	"crypto/subtle"
	"math/big"
	mathbits "math/bits"
	"sync"
)

// Curve — эллиптическая кривая в канонической форме (форме Вейерштрасса)
// y^2 = x^3 + a*x + b (mod p), заданная в ГОСТ Р 34.10-2012, 5.2.
//
// Коэффициент a у ГОСТ-кривых не равен -3, поэтому crypto/elliptic
// неприменим: elliptic.CurveParams реализует только y^2 = x^3 - 3x + b.
//
// Арифметика поля своя (см. field.go); math/big остаётся только на
// границе API и в вычислениях по модулю q, которых на одну подпись
// приходится единицы.
type Curve struct {
	name string
	p    *big.Int // характеристика поля
	a, b *big.Int // коэффициенты уравнения
	m    *big.Int // порядок группы точек
	q    *big.Int // порядок циклической подгруппы
	x, y *big.Int // координаты точки P — образующей подгруппы
	size int      // длина q в байтах: размер r, s и координат в кодировке

	f      *field
	aM, bM fe // коэффициенты уравнения в форме Монтгомери
	b3M    fe // 3b — константа полных формул сложения
	gx, gy fe // образующая в форме Монтгомери

	// Предвычисленная таблица для умножения образующей точки на скаляр.
	// Строится один раз при первом обращении и дальше только читается.
	combOnce sync.Once
	comb     []point
	combD    int
}

// Name возвращает имя набора параметров.
func (c *Curve) Name() string { return c.name }

// Size возвращает длину q в байтах. Столько же занимает каждая из величин
// r и s в кодировке подписи и каждая координата в кодировке открытого ключа.
func (c *Curve) Size() int { return c.size }

func copyInt(v *big.Int) *big.Int { return new(big.Int).Set(v) }

// P возвращает характеристику поля.
func (c *Curve) P() *big.Int { return copyInt(c.p) }

// A возвращает коэффициент a уравнения кривой.
func (c *Curve) A() *big.Int { return copyInt(c.a) }

// B возвращает коэффициент b уравнения кривой.
func (c *Curve) B() *big.Int { return copyInt(c.b) }

// M возвращает порядок группы точек.
func (c *Curve) M() *big.Int { return copyInt(c.m) }

// Q возвращает порядок циклической подгруппы.
func (c *Curve) Q() *big.Int { return copyInt(c.q) }

// Cofactor возвращает кофактор m/q.
func (c *Curve) Cofactor() *big.Int { return new(big.Int).Div(c.m, c.q) }

// Generator возвращает координаты образующей точки P.
func (c *Curve) Generator() (x, y *big.Int) { return copyInt(c.x), copyInt(c.y) }

// IsOnCurve сообщает, лежит ли точка (x, y) на кривой.
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	if x.Sign() < 0 || x.Cmp(c.p) >= 0 || y.Sign() < 0 || y.Cmp(c.p) >= 0 {
		return false
	}
	f := c.f
	var xm, ym, left, right, t fe
	f.toMont(&xm, x)
	f.toMont(&ym, y)

	f.sqr(&left, &ym)          // y^2
	f.sqr(&right, &xm)         // x^2
	f.mul(&right, &right, &xm) // x^3
	f.mul(&t, &c.aM, &xm)      // a*x
	f.add(&right, &right, &t)
	f.add(&right, &right, &c.bM)

	return f.equal(&left, &right)
}

// --- арифметика точек ------------------------------------------------------
//
// Точка задаётся однородными проективными координатами (X : Y : Z),
// аффинная точка — это (X/Z, Y/Z), нейтральный элемент — (0 : 1 : 0).
//
// Сложение и удвоение выполняются по полным формулам Renes-Costello-Batina
// для кривых в форме Вейерштрасса с произвольным a. Полными они называются
// потому, что дают верный результат для любых входов, включая совпадающие,
// противоположные и нейтральный элемент. Формулы в координатах Якоби
// дешевле, но требуют разбирать эти случаи условными переходами, то есть
// давать утечку по времени.
//
// Полнота доказана для кривых простого порядка. У наших кривых кофактор 1
// или 4, но все вычисления идут внутри подгруппы простого порядка q: она
// нечётна и потому не содержит точек порядка 2, на которых формулы могли
// бы дать исключение. Принадлежность открытого ключа этой подгруппе
// проверяется при его разборе.

type point struct {
	x, y, z fe
}

// setNeutral делает точку нейтральным элементом (0 : 1 : 0).
func (c *Curve) setNeutral(p *point) {
	p.x = fe{}
	p.y = c.f.one
	p.z = fe{}
}

func (c *Curve) isInfinity(p *point) bool { return c.f.isZero(&p.z) }

func (c *Curve) fromAffine(r *point, x, y *big.Int) {
	c.f.toMont(&r.x, x)
	c.f.toMont(&r.y, y)
	r.z = c.f.one
}

// toAffine приводит точку к аффинным координатам. Для нейтрального
// элемента возвращает (nil, nil).
func (c *Curve) toAffine(p *point) (x, y *big.Int) {
	f := c.f
	if f.isZero(&p.z) {
		return nil, nil
	}
	var zinv, xr, yr fe
	f.inv(&zinv, &p.z)
	f.mul(&xr, &p.x, &zinv)
	f.mul(&yr, &p.y, &zinv)
	return f.fromMont(&xr), f.fromMont(&yr)
}

// addPoint записывает в r сумму точек по алгоритму 1 из работы
// Renes-Costello-Batina (полное сложение, произвольное a).
// Стоимость: 12 умножений, 3 умножения на a, 2 на 3b.
func (c *Curve) addPoint(r, p, q *point) {
	f := c.f
	var t0, t1, t2, t3, t4, t5, x3, y3, z3 fe

	f.mul(&t0, &p.x, &q.x)
	f.mul(&t1, &p.y, &q.y)
	f.mul(&t2, &p.z, &q.z)
	f.add(&t3, &p.x, &p.y)
	f.add(&t4, &q.x, &q.y)
	f.mul(&t3, &t3, &t4)
	f.add(&t4, &t0, &t1)
	f.sub(&t3, &t3, &t4)
	f.add(&t4, &p.x, &p.z)
	f.add(&t5, &q.x, &q.z)
	f.mul(&t4, &t4, &t5)
	f.add(&t5, &t0, &t2)
	f.sub(&t4, &t4, &t5)
	f.add(&t5, &p.y, &p.z)
	f.add(&x3, &q.y, &q.z)
	f.mul(&t5, &t5, &x3)
	f.add(&x3, &t1, &t2)
	f.sub(&t5, &t5, &x3)
	f.mul(&z3, &c.aM, &t4)
	f.mul(&x3, &c.b3M, &t2)
	f.add(&z3, &x3, &z3)
	f.sub(&x3, &t1, &z3)
	f.add(&z3, &t1, &z3)
	f.mul(&y3, &x3, &z3)
	f.add(&t1, &t0, &t0)
	f.add(&t1, &t1, &t0)
	f.mul(&t2, &c.aM, &t2)
	f.mul(&t4, &c.b3M, &t4)
	f.add(&t1, &t1, &t2)
	f.sub(&t2, &t0, &t2)
	f.mul(&t2, &c.aM, &t2)
	f.add(&t4, &t4, &t2)
	f.mul(&t0, &t1, &t4)
	f.add(&y3, &y3, &t0)
	f.mul(&t0, &t5, &t4)
	f.mul(&x3, &t3, &x3)
	f.sub(&x3, &x3, &t0)
	f.mul(&t0, &t3, &t1)
	f.mul(&z3, &t5, &z3)
	f.add(&z3, &z3, &t0)

	r.x, r.y, r.z = x3, y3, z3
}

// doublePoint записывает в r удвоение точки по алгоритму 3 из той же
// работы. Стоимость: 8 умножений, 3 возведения в квадрат, 3 умножения на a,
// 2 на 3b.
func (c *Curve) doublePoint(r, p *point) {
	f := c.f
	var t0, t1, t2, t3, x3, y3, z3 fe

	f.sqr(&t0, &p.x)
	f.sqr(&t1, &p.y)
	f.sqr(&t2, &p.z)
	f.mul(&t3, &p.x, &p.y)
	f.add(&t3, &t3, &t3)
	f.mul(&z3, &p.x, &p.z)
	f.add(&z3, &z3, &z3)
	f.mul(&x3, &c.aM, &z3)
	f.mul(&y3, &c.b3M, &t2)
	f.add(&y3, &x3, &y3)
	f.sub(&x3, &t1, &y3)
	f.add(&y3, &t1, &y3)
	f.mul(&y3, &x3, &y3)
	f.mul(&x3, &t3, &x3)
	f.mul(&z3, &c.b3M, &z3)
	f.mul(&t2, &c.aM, &t2)
	f.sub(&t3, &t0, &t2)
	f.mul(&t3, &c.aM, &t3)
	f.add(&t3, &t3, &z3)
	f.add(&z3, &t0, &t0)
	f.add(&t0, &z3, &t0)
	f.add(&t0, &t0, &t2)
	f.mul(&t0, &t0, &t3)
	f.add(&y3, &y3, &t0)
	f.mul(&t2, &p.y, &p.z)
	f.add(&t2, &t2, &t2)
	f.mul(&t0, &t2, &t3)
	f.sub(&x3, &x3, &t0)
	f.mul(&z3, &t2, &t1)
	f.add(&z3, &z3, &z3)
	f.add(&z3, &z3, &z3)

	r.x, r.y, r.z = x3, y3, z3
}

// selectPoint выбирает из таблицы запись с номером idx, просматривая всю
// таблицу целиком: адрес обращения к памяти от idx не зависит.
func (c *Curve) selectPoint(dst *point, tbl []point, idx int) {
	f := c.f
	var acc point
	for i := range tbl {
		m := uint64(0) - uint64(subtle.ConstantTimeEq(int32(i), int32(idx)))
		f.condMove(&acc.x, &tbl[i].x, m)
		f.condMove(&acc.y, &tbl[i].y, m)
		f.condMove(&acc.z, &tbl[i].z, m)
	}
	*dst = acc
}

// scalarWindow — ширина окна при умножении произвольной точки на скаляр.
const scalarWindow = 4

// scalarMultPoint умножает точку на скаляр методом фиксированного окна.
// Число операций не зависит от скаляра, выборка из таблицы выполняется
// просмотром всех записей.
func (c *Curve) scalarMultPoint(p *point, k *big.Int) point {
	var acc, sel point
	c.setNeutral(&acc)

	tbl := make([]point, 1<<scalarWindow)
	c.setNeutral(&tbl[0])
	tbl[1] = *p
	for i := 2; i < len(tbl); i++ {
		if i%2 == 0 {
			c.doublePoint(&tbl[i], &tbl[i/2])
		} else {
			c.addPoint(&tbl[i], &tbl[i-1], p)
		}
	}

	nbits := k.BitLen()
	if n := c.q.BitLen(); n > nbits {
		nbits = n
	}
	nbits = (nbits + scalarWindow - 1) / scalarWindow * scalarWindow

	for i := nbits - scalarWindow; i >= 0; i -= scalarWindow {
		for j := 0; j < scalarWindow; j++ {
			c.doublePoint(&acc, &acc)
		}
		idx := 0
		for j := scalarWindow - 1; j >= 0; j-- {
			idx = idx<<1 | int(k.Bit(i+j))
		}
		c.selectPoint(&sel, tbl, idx)
		c.addPoint(&acc, &acc, &sel)
	}
	return acc
}

// combWidth — число блоков, на которые делится скаляр в методе гребёнки.
// Ширина выбрана как компромисс: чем она больше, тем меньше операций над
// точками, но тем дороже обходится просмотр всей таблицы при выборке.
const combWidth = 6

// combTable строит таблицу для умножения образующей точки на скаляр
// методом фиксированной гребёнки. Строится один раз на кривую.
func (c *Curve) combTable() []point {
	c.combOnce.Do(func() {
		d := (c.q.BitLen() + combWidth - 1) / combWidth
		c.combD = d

		var g point
		g.x, g.y, g.z = c.gx, c.gy, c.f.one

		base := make([]point, combWidth)
		cur := g
		for j := 0; j < combWidth; j++ {
			base[j] = cur
			for i := 0; i < d; i++ {
				c.doublePoint(&cur, &cur)
			}
		}

		tbl := make([]point, 1<<combWidth)
		c.setNeutral(&tbl[0])
		for v := 1; v < len(tbl); v++ {
			low := mathbits.TrailingZeros(uint(v))
			c.addPoint(&tbl[v], &tbl[v&(v-1)], &base[low])
		}
		c.comb = tbl
	})
	return c.comb
}

// scalarBaseMultPoint умножает образующую точку на скаляр по
// предвычисленной таблице.
func (c *Curve) scalarBaseMultPoint(k *big.Int) point {
	tbl := c.combTable()
	d := c.combD

	var acc, sel point
	c.setNeutral(&acc)
	for i := d - 1; i >= 0; i-- {
		c.doublePoint(&acc, &acc)
		idx := 0
		for j := combWidth - 1; j >= 0; j-- {
			idx = idx<<1 | int(k.Bit(j*d+i))
		}
		c.selectPoint(&sel, tbl, idx)
		c.addPoint(&acc, &acc, &sel)
	}
	return acc
}

// ScalarMult возвращает k*(x, y). Для нейтрального результата возвращает
// (nil, nil).
func (c *Curve) ScalarMult(x, y, k *big.Int) (*big.Int, *big.Int) {
	var p point
	c.fromAffine(&p, x, y)
	res := c.scalarMultPoint(&p, k)
	return c.toAffine(&res)
}

// ScalarBaseMult возвращает k*P, где P — образующая подгруппы.
func (c *Curve) ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	res := c.scalarBaseMultPoint(k)
	return c.toAffine(&res)
}

// Add возвращает сумму двух точек кривой.
func (c *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	var p1, p2, r point
	c.fromAffine(&p1, x1, y1)
	c.fromAffine(&p2, x2, y2)
	c.addPoint(&r, &p1, &p2)
	return c.toAffine(&r)
}

// InSubgroup сообщает, лежит ли точка в подгруппе простого порядка q.
//
// Для кривых с кофактором 1 это следует из принадлежности кривой. Для
// кривых с кофактором 4 проверка нужна: точка малого порядка позволила бы
// атаку на малую подгруппу и вывела бы вычисления за пределы области, где
// доказана полнота формул сложения.
func (c *Curve) InSubgroup(x, y *big.Int) bool {
	if c.Cofactor().Cmp(bigOne) == 0 {
		return true
	}
	var p point
	c.fromAffine(&p, x, y)
	res := c.scalarMultPoint(&p, c.q)
	return c.isInfinity(&res)
}

var bigOne = big.NewInt(1)
