// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
)

// FuzzPadRoundTrip: процедура 2 обратима на любых данных, а Unpad2 не
// должна падать ни на каком входе, в том числе на чужом.
func FuzzPadRoundTrip(f *testing.F) {
	f.Add([]byte{}, uint8(8))
	f.Add([]byte{0x01}, uint8(16))
	f.Add(bytes.Repeat([]byte{0xFF}, 31), uint8(16))

	f.Fuzz(func(t *testing.T, data []byte, bs uint8) {
		blockSize := int(bs%16) + 1
		padded := Pad2(data, blockSize)
		if len(padded)%blockSize != 0 || len(padded) == 0 {
			t.Fatalf("Pad2 дал длину %d при блоке %d", len(padded), blockSize)
		}
		back, err := Unpad2(padded)
		if err != nil {
			t.Fatalf("Unpad2 после Pad2: %v", err)
		}
		if !bytes.Equal(back, data) {
			t.Fatalf("Unpad2(Pad2(x)) = %x, ожидалось %x", back, data)
		}

		// Процедура 1 не обратима — она лишь дополняет до кратности.
		p1 := Pad1(data, blockSize)
		if len(p1)%blockSize != 0 {
			t.Fatalf("Pad1 дал длину %d при блоке %d", len(p1), blockSize)
		}
		if len(p1) < len(data) || !bytes.HasPrefix(p1, data) {
			t.Fatal("Pad1 изменил исходные данные")
		}

		// Unpad2 на произвольных данных: важно только отсутствие паники.
		_, _ = Unpad2(data)
	})
}

// FuzzModeRoundTrip: расшифрование обращает зашифрование во всех режимах,
// на любой длине сообщения и при любом сдвиге s.
func FuzzModeRoundTrip(f *testing.F) {
	f.Add([]byte("сообщение"), uint8(0), false)
	f.Add([]byte{}, uint8(3), true)
	f.Add(bytes.Repeat([]byte{0xAA}, 100), uint8(7), false)

	f.Fuzz(func(t *testing.T, data []byte, sSel uint8, useMagma bool) {
		b := newBlock(t, useMagma)
		bs := b.BlockSize()
		iv := make([]byte, bs)
		for i := range iv {
			iv[i] = byte(i * 7)
		}
		s := int(sSel)%bs + 1

		// Гаммирование и обратная связь по выходу.
		for _, mk := range []struct {
			name string
			new  func() (cipher.Stream, error)
		}{
			{"CTR", func() (cipher.Stream, error) { return NewCTRWithS(b, iv[:bs/2], s) }},
			{"OFB", func() (cipher.Stream, error) { return NewOFBWithS(b, iv, s) }},
		} {
			enc, err := mk.new()
			if err != nil {
				t.Fatalf("%s: %v", mk.name, err)
			}
			ct := make([]byte, len(data))
			enc.XORKeyStream(ct, data)

			dec, err := mk.new()
			if err != nil {
				t.Fatalf("%s: %v", mk.name, err)
			}
			pt := make([]byte, len(ct))
			dec.XORKeyStream(pt, ct)
			if !bytes.Equal(pt, data) {
				t.Fatalf("%s: round-trip не сошёлся", mk.name)
			}
		}

		// Обратная связь по шифртексту.
		encCFB, err := NewCFBEncrypterWithS(b, iv, s)
		if err != nil {
			t.Fatal(err)
		}
		ct := make([]byte, len(data))
		encCFB.XORKeyStream(ct, data)
		decCFB, err := NewCFBDecrypterWithS(b, iv, s)
		if err != nil {
			t.Fatal(err)
		}
		pt := make([]byte, len(ct))
		decCFB.XORKeyStream(pt, ct)
		if !bytes.Equal(pt, data) {
			t.Fatal("CFB: round-trip не сошёлся")
		}

		// Режимы, работающие целыми блоками: данные дополняются.
		padded := Pad2(data, bs)
		encCBC, err := NewCBCEncrypter(b, bytes.Repeat(iv, 2))
		if err != nil {
			t.Fatal(err)
		}
		ctb := make([]byte, len(padded))
		encCBC.CryptBlocks(ctb, padded)
		decCBC, err := NewCBCDecrypter(b, bytes.Repeat(iv, 2))
		if err != nil {
			t.Fatal(err)
		}
		ptb := make([]byte, len(ctb))
		decCBC.CryptBlocks(ptb, ctb)
		back, err := Unpad2(ptb)
		if err != nil {
			t.Fatalf("CBC: %v", err)
		}
		if !bytes.Equal(back, data) {
			t.Fatal("CBC: round-trip не сошёлся")
		}

		ecbCT := make([]byte, len(padded))
		NewECBEncrypter(b).CryptBlocks(ecbCT, padded)
		ecbPT := make([]byte, len(ecbCT))
		NewECBDecrypter(b).CryptBlocks(ecbPT, ecbCT)
		if !bytes.Equal(ecbPT, padded) {
			t.Fatal("ECB: round-trip не сошёлся")
		}
	})
}

func newBlock(t testing.TB, useMagma bool) cipher.Block {
	t.Helper()
	if useMagma {
		b, err := magma.NewCipher(bytes.Repeat([]byte{0x11}, 32))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b, err := kuznyechik.NewCipher(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
