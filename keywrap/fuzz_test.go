// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package keywrap

import (
	"bytes"
	"testing"
)

// FuzzUnwrap: завёрнутый ключ приходит извне, поэтому Unwrap обязан
// отказывать, а не падать, на любом вводе, и никогда не принимать ключ
// без сошедшейся имитовставки.
func FuzzUnwrap(f *testing.F) {
	exportKey := bytes.Repeat([]byte{0x11}, 32)
	key := bytes.Repeat([]byte{0x22}, 32)
	seed := bytes.Repeat([]byte{0x33}, 8)
	good, err := Wrap(exportKey, seed, key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, 8)
	f.Add([]byte{}, 8)
	f.Add(good[:len(good)-1], 8)

	f.Fuzz(func(t *testing.T, wrapped []byte, seedSize int) {
		out, err := Unwrap(exportKey, wrapped, seedSize)
		if err != nil {
			return
		}
		// Раз ключ принят, он обязан заворачиваться обратно в тот же
		// самый вход: иначе проверка имитовставки что-то пропустила.
		again, err := Wrap(exportKey, wrapped[:seedSize], out)
		if err != nil {
			t.Fatalf("обратное заворачивание: %v", err)
		}
		if !bytes.Equal(again, wrapped) {
			t.Fatalf("принят вход, не совпадающий с заворачиванием\n  было  %x\n  стало %x", wrapped, again)
		}
	})
}

// FuzzWrapRoundTrip: заворачивание обратимо на любых допустимых длинах.
func FuzzWrapRoundTrip(f *testing.F) {
	f.Add([]byte("ключ экспорта"), uint8(0), uint8(4))
	f.Add([]byte{}, uint8(8), uint8(8))

	f.Fuzz(func(t *testing.T, exportKey []byte, seedSel, keyBlocks uint8) {
		seedSize := int(seedSel)%(MaxSeedSize-MinSeedSize+1) + MinSeedSize
		keySize := (int(keyBlocks)%8 + 1) * 8

		seed := make([]byte, seedSize)
		for i := range seed {
			seed[i] = byte(i*13 + 1)
		}
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i * 7)
		}

		wrapped, err := Wrap(exportKey, seed, key)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Unwrap(exportKey, wrapped, seedSize)
		if err != nil {
			t.Fatalf("Unwrap после Wrap: %v", err)
		}
		if !bytes.Equal(back, key) {
			t.Fatal("round-trip не сошёлся")
		}
	})
}
