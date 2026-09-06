// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3410

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
)

func mustInt10(t testing.TB, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("некорректное число %q", s)
	}
	return v
}

// --- проверка перенесённых параметров --------------------------------------

// Самая сильная проверка транскрипции: если хоть одно из чисел p, a, b, x,
// y, q перенесено с ошибкой, эти два условия почти наверняка нарушатся.
func TestCurveParameters(t *testing.T) {
	for _, c := range AllCurves() {
		t.Run(c.Name(), func(t *testing.T) {
			gx, gy := c.Generator()

			if !c.IsOnCurve(gx, gy) {
				t.Fatal("образующая точка не лежит на кривой")
			}

			// q*P должно быть бесконечно удалённой точкой: иначе порядок
			// подгруппы указан неверно.
			x, y := c.ScalarMult(gx, gy, c.Q())
			if x != nil || y != nil {
				t.Fatalf("q*P = (%x, %x), ожидалась бесконечно удалённая точка", x, y)
			}

			// Порядок группы кратен порядку подгруппы; кофактор мал.
			cof, rem := new(big.Int).DivMod(c.M(), c.Q(), new(big.Int))
			if rem.Sign() != 0 {
				t.Fatalf("m не кратно q: остаток %x", rem)
			}
			if cof.Sign() <= 0 || cof.Cmp(big.NewInt(16)) > 0 {
				t.Fatalf("подозрительный кофактор m/q = %s", cof)
			}

			if c.A().Cmp(c.P()) >= 0 || c.B().Cmp(c.P()) >= 0 {
				t.Fatal("коэффициент a или b не приведён по модулю p")
			}
			if !c.P().ProbablyPrime(20) {
				t.Fatal("характеристика поля не простая")
			}
			if !c.Q().ProbablyPrime(20) {
				t.Fatal("порядок подгруппы не простой")
			}
		})
	}
}

// Наборы ТК 26 и CryptoPro должны совпадать покоординатно
// (RFC 9215, приложение C).
func TestParamSetAliases(t *testing.T) {
	// id-GostR3410-2001-TestParamSet из RFC 4357 и кривая из RFC 7091, 7.1 —
	// одна и та же кривая, перенесённая из двух независимых источников.
	c := TestParamSet256()
	if got, want := c.P(), mustInt10(t, "8000000000000000000000000000000000000000000000000000000000000431"); got.Cmp(want) != 0 {
		t.Errorf("p = %x", got)
	}
	if got := c.A(); got.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("a = %x, ожидалось 7", got)
	}
}

// Арифметика: сложение и удвоение должны согласовываться, а умножение на
// скаляр — с повторным сложением.
func TestScalarMultAgainstRepeatedAddition(t *testing.T) {
	c := TestParamSet256()
	gx, gy := c.Generator()

	accX, accY := gx, gy
	for k := 2; k <= 20; k++ {
		accX, accY = c.Add(accX, accY, gx, gy)
		x, y := c.ScalarMult(gx, gy, big.NewInt(int64(k)))
		if x == nil || x.Cmp(accX) != 0 || y.Cmp(accY) != 0 {
			t.Fatalf("k=%d: умножение дало (%x, %x), сложение (%x, %x)", k, x, y, accX, accY)
		}
		if !c.IsOnCurve(x, y) {
			t.Fatalf("k=%d: точка не на кривой", k)
		}
	}
}

// --- контрольный пример ГОСТ Р 34.10-2012 / RFC 7091 -----------------------

// Стандарт задаёт e напрямую, поэтому этот пример проверяет всю арифметику
// подписи, не затрагивая вопрос о переводе хэша в целое.
func TestRFC7091(t *testing.T) {
	c := TestParamSet256()

	d := mustInt10(t, "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	wantQx := mustInt10(t, "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B")
	wantQy := mustInt10(t, "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")
	e := mustInt10(t, "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	k := mustInt10(t, "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3")
	wantR := mustInt10(t, "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")
	wantS := mustInt10(t, "01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	priv, err := NewPrivateKey(c, d)
	if err != nil {
		t.Fatal(err)
	}
	if priv.X.Cmp(wantQx) != 0 || priv.Y.Cmp(wantQy) != 0 {
		t.Fatalf("Q = (%x, %x)\n  ожидалось (%x, %x)", priv.X, priv.Y, wantQx, wantQy)
	}

	r, s, ok := signWithK(priv, e, k)
	if !ok {
		t.Fatal("подпись не сформирована")
	}
	if r.Cmp(wantR) != 0 {
		t.Errorf("r = %x\n  ожидалось %x", r, wantR)
	}
	if s.Cmp(wantS) != 0 {
		t.Errorf("s = %x\n  ожидалось %x", s, wantS)
	}

	// Проверка: подставляем то же e через искусственный дайджест.
	digest := digestForE(t, c, e)
	if !VerifyDigestRS(&priv.PublicKey, digest, r, s) {
		t.Fatal("подпись не прошла проверку")
	}
}

// digestForE строит дайджест, который DigestToInt переведёт ровно в e:
// байты little-endian, длина — Size() кривой.
func digestForE(t testing.TB, c *Curve, e *big.Int) []byte {
	t.Helper()
	be := make([]byte, c.Size())
	e.FillBytes(be)
	le := make([]byte, len(be))
	for i, v := range be {
		le[len(be)-1-i] = v
	}
	return le
}

// Обе половины подписи всегда занимают ровно Size() байт, даже когда число
// короче. Стандарт печатает s контрольного примера как 63 шестнадцатеричные
// цифры (0x1456C64B...), то есть со старшим нулевым полубайтом; а если
// нулевым окажется целый старший байт — что случается примерно в одной
// подписи из 256, — наивная кодировка через Bytes() даст 63 байта вместо 64
// и сломает совместимость.
func TestSignatureFixedWidth(t *testing.T) {
	c := TestParamSet256()
	r := mustInt10(t, "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")
	s := mustInt10(t, "01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	sig, err := MarshalSignature(c, r, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 2*c.Size() {
		t.Fatalf("длина подписи %d, ожидалось %d", len(sig), 2*c.Size())
	}
	if sig[c.Size()] != 0x01 {
		t.Fatalf("s закодировано неверно: первый байт %02x, ожидался 01", sig[c.Size()])
	}
	gotR, gotS, err := ParseSignature(c, sig)
	if err != nil {
		t.Fatal(err)
	}
	if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
		t.Fatal("разбор не восстановил исходные значения")
	}

	// Короткие значения дополняются нулями слева, а не обрезаются.
	for _, small := range []*big.Int{big.NewInt(1), big.NewInt(0xff), new(big.Int).Lsh(big.NewInt(1), 200)} {
		sig, err := MarshalSignature(c, small, small)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 2*c.Size() {
			t.Fatalf("значение %x: длина подписи %d, ожидалось %d", small, len(sig), 2*c.Size())
		}
		gotR, gotS, err := ParseSignature(c, sig)
		if err != nil {
			t.Fatal(err)
		}
		if gotR.Cmp(small) != 0 || gotS.Cmp(small) != 0 {
			t.Fatalf("значение %x не восстановилось", small)
		}
	}

	// Число, не помещающееся в Size() байт, должно отвергаться.
	tooBig := new(big.Int).Lsh(big.NewInt(1), uint(c.Size()*8))
	if _, err := MarshalSignature(c, tooBig, big.NewInt(1)); err != ErrInvalidSignature {
		t.Errorf("слишком большое r принято: err = %v", err)
	}
}

// --- сквозная проверка соглашения о порядке байт ---------------------------

// Сертификаты из приложения D RFC 9215 подписаны независимой реализацией.
// Успешная проверка означает, что все четыре соглашения выбраны верно:
// перевод хэша в alpha (little-endian), порядок половин подписи в PKIX
// (s || r), выбор длины хэш-кода по идентификатору алгоритма и сама
// арифметика.

const certD2 = "MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw" +
	"IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4" +
	"YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP" +
	"7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE" +
	"aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ" +
	"yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6" +
	"DglzGOeubudp"

const certD3 = "MIIBqjCCARagAwIBAgIBCzAKBggqhQMHAQEDAzASMRAwDgYDVQQDEwdFeGFtcGxl" +
	"MCAXDTAxMDEwMTAwMDAwMFoYDzIwNTAxMjMxMDAwMDAwWjASMRAwDgYDVQQDEwdF" +
	"eGFtcGxlMIGgMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAAOBhAAEgYDh7zDVLGEz" +
	"3dmdHVxBRVz3302LTJJbvGmvFDPRVlhRWt0hRoUMMlxbgcEzvmVaqMTUQOe5io1Z" +
	"SHsMdpa8xV0R7L53NqnsNX/y/TmTH04RTLjNo1knCsfw5/9D2UGUGeph/Sq3f12f" +
	"Y1I9O1CgT2PioM9Rt8E63CFWDwvUDMnHN6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAK" +
	"BggqhQMHAQEDAwOBgQBBVwPYkvGl8/aMQ1MYmn7iB7gLVjHvnUlSmk1rVCws+hWq" +
	"LqzxH0cP3n2VSFaQPDX9j5Ve8wDZXHdTSnJKDu5wL4b6YKCBCRoj3XleHjxonuUS" +
	"o8gu4NzCZDx47qj8rNNUklWEhrIPHJ7Bl8kGmYUCYMk7y82cXDMX4ZNE4XOuNg=="

// derNext разбирает один элемент DER: возвращает его полную запись
// (с тегом и длиной), содержимое и остаток буфера. Достаточно для того,
// чтобы вынуть tbsCertificate и значение подписи; полноценный разбор X.509
// относится к этапу 5.
func derNext(b []byte) (full, content, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, nil, errors.New("DER: слишком короткий буфер")
	}
	i := 1
	n := int(b[i])
	i++
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 || len(b) < i+count {
			return nil, nil, nil, errors.New("DER: некорректная длина")
		}
		n = 0
		for j := 0; j < count; j++ {
			n = n<<8 | int(b[i+j])
		}
		i += count
	}
	if len(b) < i+n {
		return nil, nil, nil, errors.New("DER: длина выходит за буфер")
	}
	return b[:i+n], b[i : i+n], b[i+n:], nil
}

// splitCertificate вынимает из сертификата подписанную часть и значение
// подписи.
func splitCertificate(t testing.TB, pem string) (tbs, sig []byte) {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(pem, "\n", ""))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	_, body, _, err := derNext(der) // Certificate ::= SEQUENCE
	if err != nil {
		t.Fatal(err)
	}
	tbs, _, rest, err := derNext(body) // tbsCertificate целиком
	if err != nil {
		t.Fatal(err)
	}
	_, _, rest, err = derNext(rest) // signatureAlgorithm
	if err != nil {
		t.Fatal(err)
	}
	_, bits, _, err := derNext(rest) // signatureValue BIT STRING
	if err != nil {
		t.Fatal(err)
	}
	if len(bits) < 1 || bits[0] != 0 {
		t.Fatalf("BIT STRING: неожиданное число неиспользуемых бит %d", bits[0])
	}
	return tbs, bits[1:]
}

func TestRFC9215Certificates(t *testing.T) {
	cases := []struct {
		name    string
		pem     string
		curve   *Curve
		x, y    string
		hashLen int
	}{
		{
			name:    "256 бит, tc26-256-A",
			pem:     certD2,
			curve:   TC26ParamSet256A(),
			x:       "99C3DF265EA59350640BA69D1DE04418AF3FEA03EC0F85F2DD84E8BED4952774",
			y:       "E218631A69C47C122E2D516DA1C09E6BD19344D94389D1F16C0C4D4DCF96F578",
			hashLen: 32,
		},
		{
			name:  "512 бит, тестовая кривая",
			pem:   certD3,
			curve: TestParamSet512(),
			x: "115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD" +
				"5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1",
			y: "37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61" +
				"EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC",
			hashLen: 64,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := NewPublicKey(tc.curve, mustInt10(t, tc.x), mustInt10(t, tc.y))
			if err != nil {
				t.Fatalf("ключ проверки не лежит на кривой: %v", err)
			}

			tbs, sig := splitCertificate(t, tc.pem)
			if len(sig) != 2*tc.curve.Size() {
				t.Fatalf("длина подписи %d, ожидалось %d", len(sig), 2*tc.curve.Size())
			}

			var digest []byte
			if tc.hashLen == 32 {
				d := streebog.Sum256(tbs)
				digest = d[:]
			} else {
				d := streebog.Sum512(tbs)
				digest = d[:]
			}

			// PKIX (RFC 9215, раздел 2) кладёт сначала s, затем r —
			// в обратном порядке относительно самого стандарта.
			half := tc.curve.Size()
			s := new(big.Int).SetBytes(sig[:half])
			r := new(big.Int).SetBytes(sig[half:])

			if !VerifyDigestRS(pub, digest, r, s) {
				t.Fatal("подпись сертификата не прошла проверку")
			}

			// Контроль: в порядке самого стандарта (r || s) подпись не
			// должна пройти — иначе тест не различает эти два порядка.
			if VerifyDigestRS(pub, digest, s, r) {
				t.Fatal("подпись прошла и в обратном порядке — тест не различает s||r и r||s")
			}

			// Контроль: испорченная подписанная часть должна отвергаться.
			bad := append([]byte(nil), tbs...)
			bad[len(bad)-1] ^= 0x01
			var badDigest []byte
			if tc.hashLen == 32 {
				d := streebog.Sum256(bad)
				badDigest = d[:]
			} else {
				d := streebog.Sum512(bad)
				badDigest = d[:]
			}
			if VerifyDigestRS(pub, badDigest, r, s) {
				t.Fatal("подпись принята для изменённых данных")
			}
		})
	}
}

// --- формирование и проверка ----------------------------------------------

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, c := range AllCurves() {
		t.Run(c.Name(), func(t *testing.T) {
			priv, err := GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if !c.IsOnCurve(priv.X, priv.Y) {
				t.Fatal("выработанный ключ проверки не лежит на кривой")
			}

			digest := make([]byte, c.Size())
			for i := range digest {
				digest[i] = byte(i*13 + 7)
			}

			sig, err := Sign(rand.Reader, priv, digest)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(&priv.PublicKey, digest, sig) {
				t.Fatal("собственная подпись не прошла проверку")
			}

			// Изменённый дайджест отвергается.
			other := append([]byte(nil), digest...)
			other[0] ^= 0xff
			if Verify(&priv.PublicKey, other, sig) {
				t.Fatal("подпись принята для другого дайджеста")
			}

			// Изменённая подпись отвергается.
			for _, pos := range []int{0, c.Size() - 1, c.Size(), 2*c.Size() - 1} {
				bad := append([]byte(nil), sig...)
				bad[pos] ^= 0x01
				if Verify(&priv.PublicKey, digest, bad) {
					t.Fatalf("испорченная подпись принята (байт %d)", pos)
				}
			}
		})
	}
}

// Каждая подпись должна использовать новое k: одинаковые подписи одного и
// того же дайджеста означали бы детерминированный или повторяющийся нонс.
func TestSignaturesDiffer(t *testing.T) {
	c := TestParamSet256()
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, c.Size())

	first, err := Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("две подписи одного дайджеста совпали")
	}
	if !Verify(&priv.PublicKey, digest, first) || !Verify(&priv.PublicKey, digest, second) {
		t.Fatal("одна из подписей не прошла проверку")
	}
}

func TestCryptoSigner(t *testing.T) {
	c := TC26ParamSet256B()
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var signer crypto.Signer = priv
	digest := streebog.Sum256([]byte("сообщение"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}

	pub, ok := signer.Public().(*PublicKey)
	if !ok {
		t.Fatal("Public() вернул не *PublicKey")
	}
	if !Verify(pub, digest[:], sig) {
		t.Fatal("подпись через crypto.Signer не прошла проверку")
	}
	if !pub.Equal(&priv.PublicKey) || !priv.Equal(priv) {
		t.Fatal("Equal работает неверно")
	}
}

func TestDigestToInt(t *testing.T) {
	// Дайджест читается как little-endian: первый байт — младший.
	digest, err := hex.DecodeString("0102030000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := DigestToInt(digest), big.NewInt(0x030201); got.Cmp(want) != 0 {
		t.Fatalf("DigestToInt = %x, ожидалось %x", got, want)
	}
}

func TestInvalidInputs(t *testing.T) {
	c := TestParamSet256()

	if _, err := NewPrivateKey(c, big.NewInt(0)); err != ErrInvalidKey {
		t.Errorf("d = 0: err = %v", err)
	}
	if _, err := NewPrivateKey(c, c.Q()); err != ErrInvalidKey {
		t.Errorf("d = q: err = %v", err)
	}
	if _, err := NewPublicKey(c, big.NewInt(1), big.NewInt(1)); err != ErrInvalidKey {
		t.Errorf("точка вне кривой принята: err = %v", err)
	}

	priv, err := NewPrivateKey(c, big.NewInt(12345))
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, c.Size())

	// r или s вне диапазона [1, q-1] должны отвергаться.
	for _, bad := range []struct{ r, s *big.Int }{
		{big.NewInt(0), big.NewInt(1)},
		{big.NewInt(1), big.NewInt(0)},
		{c.Q(), big.NewInt(1)},
		{big.NewInt(1), c.Q()},
		{nil, big.NewInt(1)},
	} {
		if VerifyDigestRS(&priv.PublicKey, digest, bad.r, bad.s) {
			t.Errorf("принята подпись r=%v s=%v", bad.r, bad.s)
		}
	}

	if _, _, err := ParseSignature(c, make([]byte, 10)); err != ErrInvalidSignature {
		t.Errorf("короткая подпись: err = %v", err)
	}
}

// --- бенчмарки ------------------------------------------------------------

func benchmarkSign(b *testing.B, c *Curve) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	digest := make([]byte, c.Size())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(rand.Reader, priv, digest); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkVerify(b *testing.B, c *Curve) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	digest := make([]byte, c.Size())
	sig, err := Sign(rand.Reader, priv, digest)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(&priv.PublicKey, digest, sig) {
			b.Fatal("проверка не прошла")
		}
	}
}

func BenchmarkSign256(b *testing.B)   { benchmarkSign(b, TC26ParamSet256B()) }
func BenchmarkVerify256(b *testing.B) { benchmarkVerify(b, TC26ParamSet256B()) }
func BenchmarkSign512(b *testing.B)   { benchmarkSign(b, TC26ParamSet512A()) }
func BenchmarkVerify512(b *testing.B) { benchmarkVerify(b, TC26ParamSet512A()) }
