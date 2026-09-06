// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3410

import (
	"math/big"
	"sync"
)

// Именованные наборы параметров эллиптических кривых.
//
// Значения перенесены из первоисточников:
//
//   - RFC 4357, приложение с параметрами GostR3410-2001 — наборы CryptoPro
//     A, B, C и тестовый; порядок полей там (a, b, p, q, x, y);
//   - RFC 7836, приложение A — наборы ТК 26 для 512 бит и кривые в форме
//     скрученного Эдвардса; порядок полей (p, a, b, [e, d,] m, q, x, y);
//   - RFC 9215, приложение E — тестовая кривая для 512-битного ключа.
//
// RFC 9215, приложение C, отождествляет наборы ТК 26 с наборами CryptoPro:
// 256-paramSetB = CryptoPro-A, 256-paramSetC = CryptoPro-B,
// 256-paramSetD = CryptoPro-C. Соответствующие функции возвращают одну и ту
// же кривую под разными именами.
//
// Кривые в форме скрученного Эдвардса (256-paramSetA и 512-paramSetC)
// используются здесь в эквивалентной канонической форме: параметры e, d и
// координаты (u, v) для подписи не нужны.

func mustInt(hexStr string) *big.Int {
	v, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("gost3410: повреждённый параметр кривой " + hexStr)
	}
	return v
}

func newCurve(name, p, a, b, m, q, x, y string) *Curve {
	c := &Curve{
		name: name,
		p:    mustInt(p),
		a:    mustInt(a),
		b:    mustInt(b),
		m:    mustInt(m),
		q:    mustInt(q),
		x:    mustInt(x),
		y:    mustInt(y),
	}
	c.size = (c.q.BitLen() + 7) / 8

	// Предвычисления для собственной арифметики поля.
	c.f = newField(c.p)
	c.f.toMont(&c.aM, c.a)
	c.f.toMont(&c.bM, c.b)
	c.f.toMont(&c.b3M, new(big.Int).Mul(c.b, big.NewInt(3)))
	c.f.toMont(&c.gx, c.x)
	c.f.toMont(&c.gy, c.y)
	return c
}

var (
	onceTest256, once256A, once256B, once256C, once256D sync.Once
	once512A, once512B, once512C, onceTest512           sync.Once

	curveTest256, curve256A, curve256B, curve256C, curve256D *Curve
	curve512A, curve512B, curve512C, curveTest512            *Curve
)

// TestParamSet256 возвращает тестовую кривую из ГОСТ Р 34.10-2012,
// приложение А.1 (RFC 7091, 7.1; RFC 4357, id-GostR3410-2001-TestParamSet).
// Предназначена только для проверки реализации.
func TestParamSet256() *Curve {
	onceTest256.Do(func() {
		curveTest256 = newCurve("id-GostR3410-2001-TestParamSet",
			"8000000000000000000000000000000000000000000000000000000000000431",
			"7",
			"5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e",
			"8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3",
			"8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3",
			"2",
			"08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8")
	})
	return curveTest256
}

// TC26ParamSet256A возвращает id-tc26-gost-3410-2012-256-paramSetA
// (RFC 7836, приложение A.2) в канонической форме.
func TC26ParamSet256A() *Curve {
	once256A.Do(func() {
		curve256A = newCurve("id-tc26-gost-3410-2012-256-paramSetA",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
			"c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335",
			"295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513",
			"01000000000000000000000000000000003f63377f21ed98d70456bd55b0d8319c",
			"400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67",
			"91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28",
			"32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c")
	})
	return curve256A
}

// TC26ParamSet256B возвращает id-tc26-gost-3410-2012-256-paramSetB, он же
// id-GostR3410-2001-CryptoPro-A-ParamSet (RFC 4357).
func TC26ParamSet256B() *Curve {
	once256B.Do(func() {
		curve256B = newCurve("id-tc26-gost-3410-2012-256-paramSetB",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94",
			"a6",
			"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
			"ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
			"1",
			"8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14")
	})
	return curve256B
}

// TC26ParamSet256C возвращает id-tc26-gost-3410-2012-256-paramSetC, он же
// id-GostR3410-2001-CryptoPro-B-ParamSet (RFC 4357).
func TC26ParamSet256C() *Curve {
	once256C.Do(func() {
		curve256C = newCurve("id-tc26-gost-3410-2012-256-paramSetC",
			"8000000000000000000000000000000000000000000000000000000000000c99",
			"8000000000000000000000000000000000000000000000000000000000000c96",
			"3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b",
			"800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f",
			"800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f",
			"1",
			"3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc")
	})
	return curve256C
}

// TC26ParamSet256D возвращает id-tc26-gost-3410-2012-256-paramSetD, он же
// id-GostR3410-2001-CryptoPro-C-ParamSet (RFC 4357).
func TC26ParamSet256D() *Curve {
	once256D.Do(func() {
		curve256D = newCurve("id-tc26-gost-3410-2012-256-paramSetD",
			"9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
			"9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598",
			"805a",
			"9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
			"9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
			"0",
			"41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67")
	})
	return curve256D
}

// TC26ParamSet512A возвращает id-tc26-gost-3410-12-512-paramSetA
// (RFC 7836, приложение A.1).
func TC26ParamSet512A() *Curve {
	once512A.Do(func() {
		curve512A = newCurve("id-tc26-gost-3410-12-512-paramSetA",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4",
			"e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
			"3",
			"7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4")
	})
	return curve512A
}

// TC26ParamSet512B возвращает id-tc26-gost-3410-12-512-paramSetB
// (RFC 7836, приложение A.1).
func TC26ParamSet512B() *Curve {
	once512B.Do(func() {
		curve512B = newCurve("id-tc26-gost-3410-12-512-paramSetB",
			"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f",
			"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c",
			"687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116",
			"800000000000000000000000000000000000000000000000000000000000000149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd",
			"800000000000000000000000000000000000000000000000000000000000000149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd",
			"2",
			"1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd")
	})
	return curve512B
}

// TC26ParamSet512C возвращает id-tc26-gost-3410-2012-512-paramSetC
// (RFC 7836, приложение A.2) в канонической форме.
func TC26ParamSet512C() *Curve {
	once512C.Do(func() {
		curve512C = newCurve("id-tc26-gost-3410-2012-512-paramSetC",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
			"dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3",
			"b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff26336e91941aac0130cea7fd451d40b323b6a79e9da6849a5188f3bd1fc08fb4",
			"3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed",
			"e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148",
			"f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f")
	})
	return curve512C
}

// TestParamSet512 возвращает тестовую кривую для 512-битного ключа
// (RFC 9215, приложение E). Предназначена только для проверки реализации.
func TestParamSet512() *Curve {
	onceTest512.Do(func() {
		curveTest512 = newCurve("id-tc26-gost-3410-2012-512-testParamSet",
			"4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373",
			"7",
			"1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc",
			"4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df",
			"4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df",
			"24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a",
			"2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e")
	})
	return curveTest512
}

// AllCurves возвращает все именованные наборы параметров. Порядок
// стабилен и удобен для табличных тестов.
func AllCurves() []*Curve {
	return []*Curve{
		TestParamSet256(),
		TC26ParamSet256A(),
		TC26ParamSet256B(),
		TC26ParamSet256C(),
		TC26ParamSet256D(),
		TC26ParamSet512A(),
		TC26ParamSet512B(),
		TC26ParamSet512C(),
		TestParamSet512(),
	}
}
