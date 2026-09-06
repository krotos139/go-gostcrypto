// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package pkcs8 кодирует ключи подписи в формате PKCS#8 по правилам
// Р 50.1.112-2016 «Транспортный ключевой контейнер».
//
// Рекомендации расширяют PKCS#8 и PKCS#12 для ключей ГОСТ Р 34.10 и
// задают то, чего в самом PKCS#8 нет: представление секретного ключа,
// порядок байт и маскирование.
//
// # Маскирование
//
// Секретный ключ хранится не сам по себе, а как произведение с масками:
//
//	KM = K · M₁⁻¹ · … · Mₖ⁻¹ mod Q
//
// а в поле ключа лежит последовательность KM‖M₁‖…‖Mₖ. Снятие маски —
// умножение на маски обратно: K = KM · M₁ · … · Mₖ mod Q. Смысл в том,
// чтобы значение ключа не лежало в памяти в открытом виде: атака по
// побочным каналам на чтение ключа увидит только маскированное значение.
//
// Немаскированный ключ — частный случай k = 0, когда KM = K.
//
// # Порядок байт
//
// Ключ записывается в порядке little-endian, как и координаты открытого
// ключа в сертификате (п. 4 рекомендаций). Наружу этот пакет отдаёт
// значения в порядке пакета gost3410.
package pkcs8

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
)

var (
	// ErrMalformed возвращается при некорректной структуре.
	ErrMalformed = errors.New("pkcs8: некорректная структура ключа")
	// ErrUnsupported возвращается для неизвестного алгоритма.
	ErrUnsupported = errors.New("pkcs8: неподдерживаемый алгоритм")
	// ErrMaskCount возвращается при недопустимом числе масок.
	ErrMaskCount = errors.New("pkcs8: недопустимое число масок")
)

// AlgorithmIdentifier - описание алгоритма с параметрами, как в X.509.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type privateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm AlgorithmIdentifier
	PrivateKey          []byte
	Attributes          asn1.RawValue `asn1:"optional,tag:0"`
}

// keyValueInfo — вариант CHOICE, несущий вместе с маскированным ключом и
// открытый ключ (п. 8 рекомендаций).
type keyValueInfo struct {
	KeyValueMask []byte
	PublicKey    []byte
}

// reverse разворачивает байты на месте.
func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// leInt читает число в порядке little-endian.
func leInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	copy(be, b)
	reverse(be)
	return new(big.Int).SetBytes(be)
}

// leBytes записывает число в порядке little-endian ровно в n байт.
func leBytes(v *big.Int, n int) ([]byte, error) {
	if v.Sign() < 0 || v.BitLen() > n*8 {
		return nil, ErrMalformed
	}
	b := make([]byte, n)
	v.FillBytes(b)
	reverse(b)
	return b, nil
}

// unmask восстанавливает ключ из последовательности KM‖M₁‖…‖Mₖ.
//
// Снятие маски — умножение по модулю Q, а умножение переместительно,
// поэтому порядок масок на результат не влияет.
func unmask(blob []byte, c *gost3410.Curve) (*big.Int, error) {
	n := c.Size()
	if len(blob) == 0 || len(blob)%n != 0 {
		return nil, ErrMalformed
	}
	q := c.Q()
	k := leInt(blob[:n])
	for i := n; i < len(blob); i += n {
		k.Mul(k, leInt(blob[i:i+n]))
		k.Mod(k, q)
	}
	return k, nil
}

// mask строит последовательность KM‖M₁‖…‖Mₖ со случайными масками.
func mask(rnd io.Reader, d *big.Int, c *gost3410.Curve, masks int) ([]byte, error) {
	n := c.Size()
	if masks < 0 {
		return nil, ErrMaskCount
	}
	q := c.Q()

	km := new(big.Int).Set(d)
	out := make([]byte, (masks+1)*n)
	for i := 1; i <= masks; i++ {
		// Маска обязана быть обратима по модулю Q: Q простое, поэтому
		// годится любое ненулевое значение меньше Q.
		var m *big.Int
		for {
			var err error
			m, err = randomBelow(rnd, q)
			if err != nil {
				return nil, err
			}
			if m.Sign() != 0 {
				break
			}
		}
		inv := new(big.Int).ModInverse(m, q)
		if inv == nil {
			return nil, ErrMalformed
		}
		km.Mul(km, inv)
		km.Mod(km, q)

		mb, err := leBytes(m, n)
		if err != nil {
			return nil, err
		}
		copy(out[i*n:], mb)
	}
	kmb, err := leBytes(km, n)
	if err != nil {
		return nil, err
	}
	copy(out, kmb)
	return out, nil
}

// randomBelow возвращает равномерное число в диапазоне [0, max).
func randomBelow(rnd io.Reader, max *big.Int) (*big.Int, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	n := (max.BitLen() + 7) / 8
	buf := make([]byte, n)
	for {
		if _, err := io.ReadFull(rnd, buf); err != nil {
			return nil, err
		}
		v := new(big.Int).SetBytes(buf)
		// Лишние старшие разряды отбрасываются, чтобы не смещать
		// распределение отбрасыванием слишком большой доли значений.
		v.Rsh(v, uint(n*8-max.BitLen()))
		if v.Cmp(max) < 0 {
			return v, nil
		}
	}
}

// parseKeyBlob вытаскивает последовательность KM‖M₁‖…‖Mₖ из содержимого
// поля privateKey.
//
// Рекомендации описывают содержимое как GostR3410-2012-PrivateKey, то
// есть CHOICE из OCTET STRING и SEQUENCE. На практике встречается и
// третий вид: в контрольном примере приложения А байты лежат прямо в
// поле privateKey, без вложенного тега. Разбираются все три.
func parseKeyBlob(content []byte, c *gost3410.Curve) ([]byte, error) {
	n := c.Size()

	// KeyValueInfo: маскированный ключ вместе с открытым.
	if len(content) > 0 && content[0] == 0x30 {
		var kvi keyValueInfo
		if rest, err := asn1.Unmarshal(content, &kvi); err == nil && len(rest) == 0 {
			if len(kvi.KeyValueMask)%n == 0 && len(kvi.KeyValueMask) > 0 {
				return kvi.KeyValueMask, nil
			}
		}
	}
	// KeyValueMask во вложенном OCTET STRING.
	if len(content) > 0 && content[0] == 0x04 {
		var blob []byte
		if rest, err := asn1.Unmarshal(content, &blob); err == nil && len(rest) == 0 {
			if len(blob) > 0 && len(blob)%n == 0 {
				return blob, nil
			}
		}
	}
	// Байты прямо в поле privateKey.
	if len(content) > 0 && len(content)%n == 0 {
		return content, nil
	}
	return nil, ErrMalformed
}

// ParsePrivateKey разбирает ключ в формате PKCS#8 (PrivateKeyInfo).
func ParsePrivateKey(der []byte) (*gost3410.PrivateKey, error) {
	var info privateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if !info.PrivateKeyAlgorithm.Algorithm.Equal(gostasn1.OIDPublicKey256) &&
		!info.PrivateKeyAlgorithm.Algorithm.Equal(gostasn1.OIDPublicKey512) &&
		!info.PrivateKeyAlgorithm.Algorithm.Equal(gostasn1.OIDPublicKey2001) {
		return nil, ErrUnsupported
	}

	// Параметры несут идентификатор набора: по нему находится кривая.
	var params struct {
		ParamSet    asn1.ObjectIdentifier
		DigestParam asn1.ObjectIdentifier `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(info.PrivateKeyAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, ErrMalformed
	}
	curve, ok := gostasn1.CurveByOID(params.ParamSet)
	if !ok {
		return nil, ErrUnsupported
	}

	blob, err := parseKeyBlob(info.PrivateKey, curve)
	if err != nil {
		return nil, err
	}
	d, err := unmask(blob, curve)
	if err != nil {
		return nil, err
	}
	return gost3410.NewPrivateKey(curve, d)
}

// MarshalOptions настраивает кодирование ключа.
type MarshalOptions struct {
	// Masks — сколько масок наложить. Ноль означает запись ключа как
	// есть; такой вариант рекомендации прямо допускают, и его понимают
	// все известные реализации. Маскирование прячет значение ключа от
	// того, кто прочитает содержимое контейнера, но не от того, кто
	// сможет его расшифровать: маски лежат рядом.
	Masks int
	// Rand — источник случайности для масок. Нулевое значение означает
	// crypto/rand.
	Rand io.Reader
}

// MarshalPrivateKey кодирует ключ в формате PKCS#8.
func MarshalPrivateKey(priv *gost3410.PrivateKey, opts *MarshalOptions) ([]byte, error) {
	if priv == nil {
		return nil, ErrMalformed
	}
	if opts == nil {
		opts = &MarshalOptions{}
	}

	// Идентификатор алгоритма берётся из кодирования открытого ключа:
	// так выбор набора параметров остаётся в одном месте.
	spki, err := gostasn1.MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Algorithm AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &parsed); err != nil {
		return nil, ErrMalformed
	}

	blob, err := mask(opts.Rand, priv.D, priv.Curve, opts.Masks)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(privateKeyInfo{
		Version:             0,
		PrivateKeyAlgorithm: parsed.Algorithm,
		PrivateKey:          blob,
	})
}
