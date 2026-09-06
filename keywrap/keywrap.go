// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package keywrap реализует экспорт и импорт ключа по RFC 7836, п. 4.6.
//
// Схема заворачивает секретный ключ K на ключе экспорта K_e:
//
//	KEK  = KDF_GOSTR3411_2012_256(K_e, 0x26BDB878, seed)
//	MAC  = имитовставка ГОСТ 28147-89 от K на ключе KEK,
//	       начальное значение — первые восемь байт seed
//	ENC  = ГОСТ 28147-89 в режиме простой замены: K на ключе KEK
//	итог = seed || ENC || MAC
//
// Набор подстановок фиксирован: id-tc26-gost-28147-param-Z.
//
// # Это не KExp15
//
// Современная схема KExp15/KImp15 задана в Р 1323565.1.017-2018 и
// устроена иначе: она построена на "Магме" или "Кузнечике" и на режиме
// OMAC. Здесь реализована та схема, которая описана в RFC 7836 и
// встречается в ранее выпущенных контейнерах; она опирается на
// устаревший ГОСТ 28147-89. KExp15 не реализована: публично доступного
// нормативного описания найти не удалось.
package keywrap

import (
	"crypto/subtle"
	"errors"

	"github.com/krotos139/go-gostcrypto/gost3413"
	"github.com/krotos139/go-gostcrypto/kdf"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

const (
	// MACSize — длина имитовставки в завёрнутом представлении.
	MACSize = 4
	// MinSeedSize и MaxSeedSize — допустимые длины случайного вектора.
	MinSeedSize = 8
	MaxSeedSize = 16
)

// label — постоянное значение из RFC 7836, п. 4.6.
var label = []byte{0x26, 0xBD, 0xB8, 0x78}

var (
	// ErrSeedSize возвращается при недопустимой длине случайного вектора.
	ErrSeedSize = errors.New("keywrap: длина seed должна быть от 8 до 16 байт")
	// ErrKeySize возвращается, если длина заворачиваемого ключа не кратна
	// размеру блока.
	ErrKeySize = errors.New("keywrap: длина ключа должна быть кратна 8 байтам")
	// ErrMalformed возвращается при некорректном завёрнутом представлении.
	ErrMalformed = errors.New("keywrap: некорректное завёрнутое представление")
	// ErrIVSize возвращается при недопустимой длине синхропосылки.
	ErrIVSize = errors.New("keywrap: недопустимая длина синхропосылки")
	// ErrMAC возвращается, если имитовставка не сошлась: ключ экспорта не
	// тот либо данные повреждены.
	ErrMAC = errors.New("keywrap: имитовставка не совпала")
)

// derive вычисляет ключ шифрования ключа и вспомогательные значения.
func derive(exportKey, seed, key []byte) (enc, mac []byte, err error) {
	kek := kdf.Derive(exportKey, label, seed)

	// Начальным значением имитовставки служат первые восемь байт seed.
	mac, err = gost28147.MAC(kek, gost28147.ParamZ(), seed[:gost28147.BlockSize], key, MACSize)
	if err != nil {
		return nil, nil, err
	}

	b, err := gost28147.NewCipher(kek, gost28147.ParamZ())
	if err != nil {
		return nil, nil, err
	}
	enc = make([]byte, len(key))
	gost3413.NewECBEncrypter(b).CryptBlocks(enc, key)
	return enc, mac, nil
}

// Wrap заворачивает ключ key на ключе экспорта exportKey.
//
// Значение seed должно быть случайным и различным для каждого вызова на
// одном и том же ключе экспорта; его длина — от 8 до 16 байт.
func Wrap(exportKey, seed, key []byte) ([]byte, error) {
	if len(seed) < MinSeedSize || len(seed) > MaxSeedSize {
		return nil, ErrSeedSize
	}
	if len(key) == 0 || len(key)%gost28147.BlockSize != 0 {
		return nil, ErrKeySize
	}

	enc, mac, err := derive(exportKey, seed, key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(seed)+len(enc)+MACSize)
	out = append(out, seed...)
	out = append(out, enc...)
	out = append(out, mac...)
	return out, nil
}

// Unwrap восстанавливает ключ из завёрнутого представления.
//
// Длина seed из самого представления не выводится: она зависит от
// протокола, поэтому передаётся отдельно. Обычно это 8 байт.
func Unwrap(exportKey, wrapped []byte, seedSize int) ([]byte, error) {
	if seedSize < MinSeedSize || seedSize > MaxSeedSize {
		return nil, ErrSeedSize
	}
	if len(wrapped) < seedSize+gost28147.BlockSize+MACSize {
		return nil, ErrMalformed
	}
	seed := wrapped[:seedSize]
	enc := wrapped[seedSize : len(wrapped)-MACSize]
	gotMAC := wrapped[len(wrapped)-MACSize:]
	if len(enc)%gost28147.BlockSize != 0 {
		return nil, ErrMalformed
	}

	kek := kdf.Derive(exportKey, label, seed)
	b, err := gost28147.NewCipher(kek, gost28147.ParamZ())
	if err != nil {
		return nil, err
	}
	key := make([]byte, len(enc))
	gost3413.NewECBDecrypter(b).CryptBlocks(key, enc)

	wantMAC, err := gost28147.MAC(kek, gost28147.ParamZ(), seed[:gost28147.BlockSize], key, MACSize)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(wantMAC, gotMAC) != 1 {
		return nil, ErrMAC
	}
	return key, nil
}
