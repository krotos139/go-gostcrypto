// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package gost3410 реализует процессы формирования и проверки электронной
// цифровой подписи по ГОСТ Р 34.10-2012, он же RFC 7091, для ключей длиной
// 256 и 512 бит.
//
// # Что такое digest в этом пакете
//
// Подпись вычисляется не над сообщением, а над его хэш-кодом. Стандарт
// определяет целое alpha как число, двоичным представлением которого
// является вектор H, причём (RFC 7091, формула 11) младшему разряду вектора
// соответствует младший разряд числа. Хэш-код "Стрибога" в потоковом
// порядке байт устроен так же — младший байт первый, — поэтому alpha
// получается прочтением дайджеста как little-endian.
//
// Это соглашение подтверждено сквозной проверкой сертификатов из
// приложения D RFC 9215, подписанных независимой реализацией.
//
// # Два порядка величин в подписи
//
// Сам стандарт определяет подпись как конкатенацию r || s (6.1). PKIX и CMS
// (RFC 9215, раздел 2) используют обратный порядок: сначала s, затем r.
// MarshalSignature и ParseSignature работают в порядке стандарта; для
// сертификатов половины нужно поменять местами.
//
// # Побочные каналы
//
// Арифметика построена на math/big, который не является constant-time.
// Пакет пригоден для проверки подписей и для задач, где противник не
// измеряет время операций с секретным ключом. См. README.
package gost3410

import (
	"crypto"
	"errors"
	"io"
	"math/big"
)

var (
	// ErrInvalidSignature возвращается при некорректной длине или
	// недопустимых значениях в подписи.
	ErrInvalidSignature = errors.New("gost3410: некорректная подпись")
	// ErrInvalidKey возвращается, если ключ не соответствует кривой.
	ErrInvalidKey = errors.New("gost3410: некорректный ключ")
	// ErrRandom возвращается, если не удалось получить случайные данные.
	ErrRandom = errors.New("gost3410: не удалось выработать случайное число")
)

// PublicKey — ключ проверки подписи: точка Q = d*P на кривой.
type PublicKey struct {
	Curve *Curve
	X, Y  *big.Int
}

// PrivateKey — ключ подписи d вместе с соответствующим ключом проверки.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

var _ crypto.Signer = (*PrivateKey)(nil)

// Public возвращает ключ проверки подписи.
func (priv *PrivateKey) Public() crypto.PublicKey { return &priv.PublicKey }

// Equal сообщает, совпадают ли ключи проверки.
func (pub *PublicKey) Equal(other crypto.PublicKey) bool {
	o, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return pub.Curve == o.Curve && pub.X.Cmp(o.X) == 0 && pub.Y.Cmp(o.Y) == 0
}

// Equal сообщает, совпадают ли ключи подписи.
func (priv *PrivateKey) Equal(other crypto.PrivateKey) bool {
	o, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.D.Cmp(o.D) == 0 && priv.PublicKey.Equal(&o.PublicKey)
}

// randomBelow возвращает равномерное случайное число в диапазоне [1, max).
func randomBelow(rand io.Reader, max *big.Int) (*big.Int, error) {
	size := (max.BitLen() + 7) / 8
	buf := make([]byte, size)
	// Лишние старшие разряды маскируются, чтобы отбраковка не была слишком
	// частой; цикл сохраняет равномерность распределения.
	mask := byte(0xff)
	if excess := uint(size*8 - max.BitLen()); excess > 0 {
		mask = byte(0xff >> excess)
	}
	for i := 0; i < 1000; i++ {
		if _, err := io.ReadFull(rand, buf); err != nil {
			return nil, ErrRandom
		}
		buf[0] &= mask
		v := new(big.Int).SetBytes(buf)
		if v.Sign() > 0 && v.Cmp(max) < 0 {
			return v, nil
		}
	}
	return nil, ErrRandom
}

// GenerateKey вырабатывает ключ подписи для заданной кривой.
func GenerateKey(c *Curve, rand io.Reader) (*PrivateKey, error) {
	d, err := randomBelow(rand, c.q)
	if err != nil {
		return nil, err
	}
	x, y := c.ScalarBaseMult(d)
	if x == nil {
		return nil, ErrInvalidKey
	}
	return &PrivateKey{PublicKey: PublicKey{Curve: c, X: x, Y: y}, D: d}, nil
}

// NewPrivateKey создаёт ключ подписи по заданному d и вычисляет
// соответствующий ключ проверки.
func NewPrivateKey(c *Curve, d *big.Int) (*PrivateKey, error) {
	if d == nil || d.Sign() <= 0 || d.Cmp(c.q) >= 0 {
		return nil, ErrInvalidKey
	}
	x, y := c.ScalarBaseMult(d)
	if x == nil {
		return nil, ErrInvalidKey
	}
	return &PrivateKey{
		PublicKey: PublicKey{Curve: c, X: x, Y: y},
		D:         new(big.Int).Set(d),
	}, nil
}

// NewPublicKey создаёт ключ проверки, убеждаясь, что точка лежит на кривой
// и принадлежит подгруппе простого порядка.
//
// Вторая проверка нужна для кривых с кофактором 4 (256-paramSetA и
// 512-paramSetC): точка малого порядка позволила бы атаку на малую
// подгруппу и вывела бы вычисления за пределы области, где доказана
// полнота формул сложения. Для кривых с кофактором 1 она бесплатна, для
// остальных стоит одного умножения точки на скаляр.
func NewPublicKey(c *Curve, x, y *big.Int) (*PublicKey, error) {
	if !c.IsOnCurve(x, y) {
		return nil, ErrInvalidKey
	}
	if !c.InSubgroup(x, y) {
		return nil, ErrInvalidKey
	}
	return &PublicKey{Curve: c, X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}, nil
}

// DigestToInt переводит хэш-код в целое alpha по формуле (11) стандарта:
// байты дайджеста в потоковом порядке читаются как little-endian.
func DigestToInt(digest []byte) *big.Int {
	be := make([]byte, len(digest))
	for i, v := range digest {
		be[len(digest)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}

// digestToE приводит хэш-код к значению e из шага 2 процесса подписи:
// e = alpha mod q, а при e = 0 — единица.
func (c *Curve) digestToE(digest []byte) *big.Int {
	e := new(big.Int).Mod(DigestToInt(digest), c.q)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

// signWithK выполняет шаги 4-6 процесса формирования подписи при заданном k.
// Возвращает ok = false, если по стандарту требуется выбрать другое k.
func signWithK(priv *PrivateKey, e, k *big.Int) (r, s *big.Int, ok bool) {
	c := priv.Curve

	cx, _ := c.ScalarBaseMult(k)
	if cx == nil {
		return nil, nil, false
	}
	r = new(big.Int).Mod(cx, c.q)
	if r.Sign() == 0 {
		return nil, nil, false
	}

	s = new(big.Int).Mul(r, priv.D)
	s.Add(s, new(big.Int).Mul(k, e))
	s.Mod(s, c.q)
	if s.Sign() == 0 {
		return nil, nil, false
	}
	return r, s, true
}

// SignDigestRS формирует подпись хэш-кода и возвращает её как пару чисел
// (ГОСТ Р 34.10-2012, 6.1).
func SignDigestRS(rand io.Reader, priv *PrivateKey, digest []byte) (r, s *big.Int, err error) {
	c := priv.Curve
	e := c.digestToE(digest)

	for i := 0; i < 100; i++ {
		k, err := randomBelow(rand, c.q)
		if err != nil {
			return nil, nil, err
		}
		if r, s, ok := signWithK(priv, e, k); ok {
			return r, s, nil
		}
	}
	return nil, nil, ErrRandom
}

// VerifyDigestRS проверяет подпись, заданную парой чисел
// (ГОСТ Р 34.10-2012, 6.2).
func VerifyDigestRS(pub *PublicKey, digest []byte, r, s *big.Int) bool {
	c := pub.Curve
	if r == nil || s == nil {
		return false
	}
	if r.Sign() <= 0 || r.Cmp(c.q) >= 0 || s.Sign() <= 0 || s.Cmp(c.q) >= 0 {
		return false
	}

	e := c.digestToE(digest)
	v := new(big.Int).ModInverse(e, c.q)
	if v == nil {
		return false
	}

	z1 := new(big.Int).Mul(s, v)
	z1.Mod(z1, c.q)
	z2 := new(big.Int).Mul(r, v)
	z2.Mod(z2, c.q)
	z2.Sub(c.q, z2)
	z2.Mod(z2, c.q)

	p1 := c.scalarBaseMultPoint(z1)
	var q, p2, sum point
	c.fromAffine(&q, pub.X, pub.Y)
	p2 = c.scalarMultPoint(&q, z2)
	c.addPoint(&sum, &p1, &p2)
	cx, _ := c.toAffine(&sum)
	if cx == nil {
		return false
	}

	return new(big.Int).Mod(cx, c.q).Cmp(r) == 0
}

// MarshalSignature кодирует подпись в порядке стандарта: r || s, каждое
// число — big-endian ровно в Size() байт, ведущие нули сохраняются.
//
// PKIX и CMS используют обратный порядок половин, s || r.
func MarshalSignature(c *Curve, r, s *big.Int) ([]byte, error) {
	if r.Sign() < 0 || s.Sign() < 0 ||
		r.BitLen() > c.size*8 || s.BitLen() > c.size*8 {
		return nil, ErrInvalidSignature
	}
	sig := make([]byte, 2*c.size)
	r.FillBytes(sig[:c.size])
	s.FillBytes(sig[c.size:])
	return sig, nil
}

// ParseSignature разбирает подпись в порядке стандарта: r || s.
func ParseSignature(c *Curve, sig []byte) (r, s *big.Int, err error) {
	if len(sig) != 2*c.size {
		return nil, nil, ErrInvalidSignature
	}
	return new(big.Int).SetBytes(sig[:c.size]),
		new(big.Int).SetBytes(sig[c.size:]), nil
}

// Sign формирует подпись хэш-кода в кодировке r || s.
func Sign(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := SignDigestRS(rand, priv, digest)
	if err != nil {
		return nil, err
	}
	return MarshalSignature(priv.Curve, r, s)
}

// Verify проверяет подпись хэш-кода в кодировке r || s.
func Verify(pub *PublicKey, digest, sig []byte) bool {
	r, s, err := ParseSignature(pub.Curve, sig)
	if err != nil {
		return false
	}
	return VerifyDigestRS(pub, digest, r, s)
}

// Sign реализует crypto.Signer. Аргумент opts не используется: длина
// хэш-кода определяется вызывающей стороной, а не пакетом.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return Sign(rand, priv, digest)
}
