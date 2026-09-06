// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/krotos139/go-gostcrypto/gost3413"
)

// Экспорт и импорт ключа KExp15/KImp15 — Р 1323565.1.017-2018,
// в открытом доступе описан в RFC 9189, п. 8.2.1.
//
//	KExp15(S, K_mac, K_enc, IV):
//	  CEK_MAC = OMAC(K_mac, IV ‖ S)
//	  SExp    = CTR(K_enc, IV, S ‖ CEK_MAC)
//
// Импорт обратен: шифртекст расшифровывается, имитовставка пересчитывается
// и сверяется.
//
// В отличие от схемы из RFC 7836, п. 4.6 (функции Wrap и Unwrap), здесь
// нет ни ГОСТ 28147-89, ни диверсификации: используются «Магма» или
// «Кузнечик» и режимы из ГОСТ Р 34.13-2015. Это современная схема.
//
// # Требования к параметрам
//
// Ключи K_mac и K_enc обязаны быть независимыми: имитовставка защищает
// шифртекст, и общий ключ разрушил бы это разделение. Значение IV не
// должно повторяться ни при какой паре ключей.

// ErrBlockMismatch возвращается, если шифры имитовставки и шифрования
// имеют разный размер блока.
var ErrBlockMismatch = errors.New("keywrap: шифры с разным размером блока")

// ErrExportedSize возвращается, если экспортированное представление
// короче имитовставки.
var ErrExportedSize = errors.New("keywrap: слишком короткое представление ключа")

// checkKExpParams проверяет общие для обеих операций условия.
func checkKExpParams(macCipher, encCipher cipher.Block, iv []byte) (n int, err error) {
	n = macCipher.BlockSize()
	if encCipher.BlockSize() != n {
		return 0, ErrBlockMismatch
	}
	// Синхропосылка режима гаммирования занимает половину блока.
	if len(iv) != n/2 {
		return 0, ErrIVSize
	}
	return n, nil
}

// omac вычисляет имитовставку длиной в блок.
func omac(b cipher.Block, data []byte) ([]byte, error) {
	m, err := gost3413.NewMAC(b, b.BlockSize())
	if err != nil {
		return nil, err
	}
	m.Write(data)
	return m.Sum(nil), nil
}

// KExp15 экспортирует секрет secret на ключах macCipher и encCipher.
//
// Оба шифра должны быть созданы на независимых ключах. Длина iv —
// половина блока. Результат длиннее секрета ровно на блок.
func KExp15(macCipher, encCipher cipher.Block, iv, secret []byte) ([]byte, error) {
	n, err := checkKExpParams(macCipher, encCipher, iv)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, ErrKeySize
	}

	// CEK_MAC = OMAC(K_mac, IV ‖ S).
	tag, err := omac(macCipher, append(append([]byte(nil), iv...), secret...))
	if err != nil {
		return nil, err
	}

	// SExp = CTR(K_enc, IV, S ‖ CEK_MAC).
	plain := make([]byte, 0, len(secret)+n)
	plain = append(plain, secret...)
	plain = append(plain, tag...)

	st, err := gost3413.NewCTR(encCipher, iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	st.XORKeyStream(out, plain)
	return out, nil
}

// KImp15 восстанавливает секрет из экспортированного представления.
//
// Возвращает ErrMAC, если имитовставка не сошлась: ключи не те либо
// представление изменено.
func KImp15(macCipher, encCipher cipher.Block, iv, exported []byte) ([]byte, error) {
	n, err := checkKExpParams(macCipher, encCipher, iv)
	if err != nil {
		return nil, err
	}
	if len(exported) <= n {
		return nil, ErrExportedSize
	}

	st, err := gost3413.NewCTR(encCipher, iv)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(exported))
	st.XORKeyStream(plain, exported)

	secret, gotTag := plain[:len(plain)-n], plain[len(plain)-n:]
	wantTag, err := omac(macCipher, append(append([]byte(nil), iv...), secret...))
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(wantTag, gotTag) != 1 {
		return nil, ErrMAC
	}
	return secret, nil
}
