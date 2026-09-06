// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package vko реализует алгоритмы выработки общего ключа
// VKO_GOSTR3410_2012_256 и VKO_GOSTR3410_2012_512 из Р 50.1.113-2016
// (RFC 7836, п. 4.3).
//
// Общий ключ вырабатывается из своего ключа подписи, чужого ключа
// проверки и параметра UKM:
//
//	K(x, y, UKM) = (m/q * UKM * x mod q) * (y*P)
//	KEK_VKO_256  = H_256(K)
//	KEK_VKO_512  = H_512(K)
//
// где m — порядок группы точек, q — порядок подгруппы, m/q — кофактор.
// Обе стороны получают одну и ту же точку, поскольку x*(y*P) = y*(x*P).
//
// # Порядок байт
//
// RFC 7836 не описывает, как точка K превращается в байты перед
// хэшированием. Соглашение восстановлено по контрольным примерам
// приложения B того же RFC и проверено тестами: и UKM, и обе координаты
// точки записываются в порядке от младшего байта к старшему, K = x || y.
//
// Это согласуется с кодировкой ключа проверки в PKIX (RFC 9215, п. 4.3),
// которая тоже little-endian, и противоположно кодировке r и s в подписи,
// которые big-endian. Внутри одного протокола встречаются оба порядка.
//
// # Отличие от версии 2001 года
//
// RFC 4357, п. 5.2, задаёт ту же формулу без множителя m/q. На кривых с
// кофактором 1 — а это все наборы CryptoPro и 512-paramSetA/B — результаты
// совпадают. Расхождение проявляется на кривых с кофактором 4:
// 256-paramSetA и 512-paramSetC. Единственные контрольные примеры ВКО в
// RFC 7836 построены на кривой с кофактором 1, поэтому именно то, чем
// версия 2012 года отличается от версии 2001, официальными векторами не
// проверяется.
package vko

import (
	"errors"
	"math/big"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
)

var (
	// ErrCurveMismatch возвращается, если ключи заданы на разных кривых.
	ErrCurveMismatch = errors.New("vko: ключи заданы на разных кривых")
	// ErrUKM возвращается при недопустимом значении UKM.
	ErrUKM = errors.New("vko: UKM должен быть положительным")
	// ErrDegenerate возвращается, если общая точка вырождена.
	ErrDegenerate = errors.New("vko: общая точка вырождена")
)

// UKMFromBytes переводит октетную строку UKM в число. Байты читаются от
// младшего к старшему — так записаны контрольные примеры RFC 7836.
func UKMFromBytes(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i, v := range b {
		be[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}

// SharedPoint вычисляет общую точку K = (m/q * UKM * d mod q) * Q.
// Возвращает её координаты.
func SharedPoint(priv *gost3410.PrivateKey, pub *gost3410.PublicKey, ukm *big.Int) (x, y *big.Int, err error) {
	if priv.Curve != pub.Curve {
		return nil, nil, ErrCurveMismatch
	}
	if ukm == nil || ukm.Sign() <= 0 {
		return nil, nil, ErrUKM
	}
	c := priv.Curve

	// Кофактор m/q. У всех наборов параметров он равен 1 или 4.
	coef := new(big.Int).Div(c.M(), c.Q())
	coef.Mul(coef, ukm)
	coef.Mul(coef, priv.D)
	coef.Mod(coef, c.Q())
	if coef.Sign() == 0 {
		return nil, nil, ErrDegenerate
	}

	x, y = c.ScalarMult(pub.X, pub.Y, coef)
	if x == nil {
		return nil, nil, ErrDegenerate
	}
	return x, y, nil
}

// marshalPoint записывает точку так, как её ожидает хэш-функция:
// x и y по Size() байт каждая, от младшего байта к старшему.
func marshalPoint(c *gost3410.Curve, x, y *big.Int) []byte {
	size := c.Size()
	out := make([]byte, 2*size)
	x.FillBytes(out[:size])
	y.FillBytes(out[size:])
	reverse(out[:size])
	reverse(out[size:])
	return out
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// KEK256 вырабатывает 256-битный общий ключ (VKO_GOSTR3410_2012_256).
// Применим к ключам длиной как 256, так и 512 бит.
func KEK256(priv *gost3410.PrivateKey, pub *gost3410.PublicKey, ukm *big.Int) ([]byte, error) {
	x, y, err := SharedPoint(priv, pub, ukm)
	if err != nil {
		return nil, err
	}
	sum := streebog.Sum256(marshalPoint(priv.Curve, x, y))
	return sum[:], nil
}

// KEK512 вырабатывает 512-битный общий ключ (VKO_GOSTR3410_2012_512).
// Предназначен для ключей длиной 512 бит.
func KEK512(priv *gost3410.PrivateKey, pub *gost3410.PublicKey, ukm *big.Int) ([]byte, error) {
	x, y, err := SharedPoint(priv, pub, ukm)
	if err != nil {
		return nil, err
	}
	sum := streebog.Sum512(marshalPoint(priv.Curve, x, y))
	return sum[:], nil
}
