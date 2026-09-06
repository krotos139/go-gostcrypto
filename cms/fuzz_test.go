// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
)

// FuzzParse проверяет разбор недоверенного ввода. Разбор подписи —
// единственное место библиотеки, куда данные приходят от кого угодно,
// поэтому от него требуется одно: не падать и не зацикливаться на любом
// входе, каким бы он ни был.
func FuzzParse(f *testing.F) {
	priv, cert := newSignerPair(f, gost3410.TC26ParamSet256A(), "fuzz", 1)
	content := []byte("подписанное содержимое")

	for _, opts := range []*SignOptions{
		{Detached: true},
		{},
		{Detached: true, SigningTime: time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)},
	} {
		der, err := Sign(rand.Reader, content, cert, priv, opts)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		sd, err := Parse(der)
		if err != nil {
			return
		}
		if len(sd.Signers) == 0 {
			t.Fatal("разбор удался, но подписантов нет")
		}
		// Проверка тоже обязана быть устойчивой: ей достаются те же
		// самые непроверенные поля.
		_ = sd.Verify(content)
		_ = sd.Verify(nil)
		for _, s := range sd.Signers {
			_ = sd.VerifySigner(s, nil)
		}
	})
}

// FuzzDERElements проверяет разбор последовательности элементов DER:
// именно он ходит по длинам, пришедшим из недоверенного ввода.
func FuzzDERElements(f *testing.F) {
	f.Add([]byte{0x30, 0x01, 0x00})
	f.Add([]byte{0x04, 0x81, 0x02, 0xAA, 0xBB})
	f.Add([]byte{0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		elems, err := derElements(b)
		if err != nil {
			return
		}
		// Успешный разбор обязан покрывать вход ровно и без пересечений.
		var total int
		for _, e := range elems {
			if len(e) == 0 {
				t.Fatal("пустой элемент")
			}
			total += len(e)
		}
		if total != len(b) {
			t.Fatalf("сумма длин элементов %d, длина входа %d", total, len(b))
		}
		if !bytes.Equal(bytes.Join(elems, nil), b) {
			t.Fatal("склейка элементов не совпадает со входом")
		}
	})
}
