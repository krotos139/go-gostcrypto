// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package mgm

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
)

func fuzzAEAD(t testing.TB, useMagma bool, tagSize int) (cipher.AEAD, bool) {
	var b cipher.Block
	var err error
	if useMagma {
		b, err = magma.NewCipher(bytes.Repeat([]byte{0x33}, 32))
	} else {
		b, err = kuznyechik.NewCipher(bytes.Repeat([]byte{0x44}, 32))
	}
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewMGM(b, tagSize)
	if err != nil {
		// Недопустимая длина имитовставки — вход отбрасывается.
		return nil, false
	}
	return a, true
}

// FuzzMGMRoundTrip: Open обращает Seal, а любое изменение шифртекста,
// связанных данных или синхропосылки обязано приводить к отказу.
func FuzzMGMRoundTrip(f *testing.F) {
	f.Add([]byte("текст"), []byte("связанные данные"), false, uint8(16))
	f.Add([]byte{}, []byte("только связанные"), true, uint8(8))
	f.Add(bytes.Repeat([]byte{0x55}, 64), []byte{}, false, uint8(16))

	f.Fuzz(func(t *testing.T, pt, ad []byte, useMagma bool, ts uint8) {
		// Стандарт требует, чтобы хотя бы одно из полей было непустым;
		// на пустых обоих Seal намеренно паникует, как и положено
		// реализации cipher.AEAD при нарушении предусловия.
		if len(pt) == 0 && len(ad) == 0 {
			return
		}
		tagSize := int(ts)
		aead, ok := fuzzAEAD(t, useMagma, tagSize)
		if !ok {
			return
		}

		nonce := make([]byte, aead.NonceSize())
		for i := range nonce {
			nonce[i] = byte(i + 1)
		}
		// Старший бит первого байта синхропосылки обязан быть нулевым.
		nonce[0] &= 0x7f

		ct := aead.Seal(nil, nonce, pt, ad)
		if len(ct) != len(pt)+aead.Overhead() {
			t.Fatalf("длина шифртекста %d при открытом тексте %d", len(ct), len(pt))
		}

		back, err := aead.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Fatalf("Open после Seal: %v", err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatal("round-trip не сошёлся")
		}

		// Порча шифртекста или имитовставки.
		for _, pos := range []int{0, len(ct) / 2, len(ct) - 1} {
			if pos < 0 {
				continue
			}
			bad := append([]byte(nil), ct...)
			bad[pos] ^= 0x01
			if _, err := aead.Open(nil, nonce, bad, ad); err == nil {
				t.Fatalf("изменённый байт %d принят", pos)
			}
		}

		// Порча связанных данных.
		if len(ad) > 0 {
			badAD := append([]byte(nil), ad...)
			badAD[0] ^= 0x01
			if _, err := aead.Open(nil, nonce, ct, badAD); err == nil {
				t.Fatal("изменённые связанные данные приняты")
			}
		}

		// Другая синхропосылка.
		badNonce := append([]byte(nil), nonce...)
		badNonce[len(badNonce)-1] ^= 0x01
		if _, err := aead.Open(nil, badNonce, ct, ad); err == nil {
			t.Fatal("чужая синхропосылка принята")
		}
	})
}

// FuzzMGMOpen: Open на произвольном вводе обязан отказывать, а не падать.
func FuzzMGMOpen(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add(bytes.Repeat([]byte{0x00}, 17), false)

	f.Fuzz(func(t *testing.T, ct []byte, useMagma bool) {
		aead, ok := fuzzAEAD(t, useMagma, 16)
		if !ok {
			return
		}
		if useMagma {
			// У "Магмы" имитовставка не длиннее блока.
			aead, ok = fuzzAEAD(t, true, 8)
			if !ok {
				return
			}
		}
		nonce := make([]byte, aead.NonceSize())
		nonce[0] = 0x01
		if _, err := aead.Open(nil, nonce, ct, nil); err == nil && len(ct) < aead.Overhead() {
			t.Fatal("принят шифртекст короче имитовставки")
		}
	})
}
