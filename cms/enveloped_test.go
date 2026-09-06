// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

func TestEnvelopedRoundTrip(t *testing.T) {
	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, cert := newSignerPair(t, tc.curve, "получатель", 1)

			// Длины вокруг границы размешивания ключа: она наступает
			// каждые 1024 байта, и ошибка там проявляется только на
			// длинных сообщениях.
			for _, n := range []int{1, 8, 100, 1023, 1024, 1025, 2048, 3000} {
				content := make([]byte, n)
				for i := range content {
					content[i] = byte(i * 7)
				}

				der, err := Encrypt(rand.Reader, content, []*x509.Certificate{cert}, nil)
				if err != nil {
					t.Fatalf("длина %d: %v", n, err)
				}
				ed, err := ParseEnvelopedData(der)
				if err != nil {
					t.Fatalf("длина %d: %v", n, err)
				}
				back, err := ed.Decrypt(priv, cert)
				if err != nil {
					t.Fatalf("длина %d: %v", n, err)
				}
				if !bytes.Equal(back, content) {
					t.Fatalf("длина %d: round-trip не сошёлся", n)
				}
			}
		})
	}
}

func TestEnvelopedManyRecipients(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	privA, certA := newSignerPair(t, c, "первый", 1)
	privB, certB := newSignerPair(t, c, "второй", 2)
	privC, certC := newSignerPair(t, c, "третий", 3)

	content := []byte("сообщение для троих")
	der, err := Encrypt(rand.Reader, content, []*x509.Certificate{certA, certB, certC}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(ed.Recipients) != 3 {
		t.Fatalf("получателей: %d", len(ed.Recipients))
	}

	for i, r := range []struct {
		priv *gost3410.PrivateKey
		cert *x509.Certificate
	}{{privA, certA}, {privB, certB}, {privC, certC}} {
		back, err := ed.Decrypt(r.priv, r.cert)
		if err != nil {
			t.Fatalf("получатель %d: %v", i, err)
		}
		if !bytes.Equal(back, content) {
			t.Fatalf("получатель %d: содержимое не совпало", i)
		}
	}

	// Посторонний ключ расшифровать не должен.
	privX, certX := newSignerPair(t, c, "посторонний", 4)
	if _, err := ed.Decrypt(privX, certX); err != ErrNoRecipient {
		t.Errorf("посторонний получатель: err = %v", err)
	}
	// И без указания сертификата тоже.
	if _, err := ed.Decrypt(privX, nil); err != ErrNoRecipient {
		t.Errorf("посторонний ключ без сертификата: err = %v", err)
	}
}

// Ключ одного получателя не должен подходить к записи другого.
func TestEnvelopedRejectsWrongKey(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	privA, certA := newSignerPair(t, c, "первый", 1)
	_, certB := newSignerPair(t, c, "второй", 2)

	der, err := Encrypt(rand.Reader, []byte("тайна"), []*x509.Certificate{certB}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ed.Decrypt(privA, certA); err != ErrNoRecipient {
		t.Errorf("чужой ключ: err = %v", err)
	}
}

// Порча имитовставки завёрнутого ключа обязана ловиться.
func TestEnvelopedDetectsTampering(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "получатель", 1)
	content := []byte("сообщение, которое испортят")

	der, err := Encrypt(rand.Reader, content, []*x509.Certificate{cert}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Ищем завёрнутый ключ и портим его имитовставку.
	ed, err := ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	ed.Recipients[0].transport.SessionEncryptedKey.MACKey[0] ^= 0x01
	if _, err := ed.Decrypt(priv, cert); err == nil {
		t.Error("испорченная имитовставка принята")
	}

	// Порча самого шифртекста имитовставкой не защищена — это свойство
	// формата, а не изъян реализации: содержимое расшифруется в мусор.
	ed2, err := ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	ed2.encrypted = append([]byte(nil), ed2.encrypted...)
	ed2.encrypted[0] ^= 0x01
	back, err := ed2.Decrypt(priv, cert)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(back, content) {
		t.Error("изменение шифртекста не повлияло на результат")
	}
}

// Разные наборы подстановок дают разный шифртекст и оба расшифровываются.
func TestEnvelopedParamSets(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "получатель", 1)
	content := []byte("проверка наборов подстановок")

	for _, oid := range []asn1.ObjectIdentifier{
		gostasn1.OIDCipherCryptoProA,
		gostasn1.OIDCipherCryptoProB,
		gostasn1.OIDCipherCryptoProC,
		gostasn1.OIDCipherCryptoProD,
		gostasn1.OIDCipherParamZ,
	} {
		der, err := Encrypt(rand.Reader, content, []*x509.Certificate{cert}, &EncryptOptions{ParamSet: oid})
		if err != nil {
			t.Fatalf("%v: %v", oid, err)
		}
		ed, err := ParseEnvelopedData(der)
		if err != nil {
			t.Fatalf("%v: %v", oid, err)
		}
		back, err := ed.Decrypt(priv, cert)
		if err != nil {
			t.Fatalf("%v: %v", oid, err)
		}
		if !bytes.Equal(back, content) {
			t.Errorf("%v: содержимое не совпало", oid)
		}
	}

	// Неизвестный набор подстановок отвергается.
	if _, err := Encrypt(rand.Reader, content, []*x509.Certificate{cert}, &EncryptOptions{
		ParamSet: asn1.ObjectIdentifier{1, 2, 3, 4},
	}); err != gostasn1.ErrUnknownParamSet {
		t.Errorf("неизвестный набор: err = %v", err)
	}
}

func TestEnvelopedParseErrors(t *testing.T) {
	if _, err := ParseEnvelopedData(nil); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}

	// Подписанное сообщение зашифрованным не является.
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "подписант", 1)
	signed, err := Sign(rand.Reader, []byte("x"), cert, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelopedData(signed); err != ErrUnsupported {
		t.Errorf("подписанное сообщение: err = %v", err)
	}

	if _, err := Encrypt(rand.Reader, []byte("x"), nil, nil); err != ErrRecipients {
		t.Errorf("пустой список получателей: err = %v", err)
	}

	// Обрезка не должна приводить к панике.
	good, err := Encrypt(rand.Reader, []byte("данные"), []*x509.Certificate{cert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n < len(good); n += 11 {
		if _, err := ParseEnvelopedData(good[:n]); err == nil {
			t.Fatalf("обрезка до %d байт принята", n)
		}
	}
}

// Ключевое размешивание обязано происходить: без него шифртекст за
// границей 1024 байт совпал бы с обычным гаммированием на исходном ключе.
func TestMeshingHappens(t *testing.T) {
	key := make([]byte, gost28147.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, gost28147.BlockSize)
	data := make([]byte, 2048)

	meshed, err := gost28147.NewCFBEncrypterMeshed(key, gost28147.ParamCryptoProA(), iv)
	if err != nil {
		t.Fatal(err)
	}
	withMesh := make([]byte, len(data))
	meshed.XORKeyStream(withMesh, data)

	b, err := gost28147.NewCipher(key, gost28147.ParamCryptoProA())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gost28147.NewCFBEncrypter(b, iv)
	if err != nil {
		t.Fatal(err)
	}
	noMesh := make([]byte, len(data))
	plain.XORKeyStream(noMesh, data)

	// До границы всё совпадает.
	if !bytes.Equal(withMesh[:1024], noMesh[:1024]) {
		t.Error("до границы размешивания результаты разошлись")
	}
	// После — обязано разойтись.
	if bytes.Equal(withMesh[1024:], noMesh[1024:]) {
		t.Error("после границы размешивания результаты совпали — размешивания не было")
	}

	// И расшифрование обязано вернуть исходное.
	dec, err := gost28147.NewCFBDecrypterMeshed(key, gost28147.ParamCryptoProA(), iv)
	if err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(withMesh))
	dec.XORKeyStream(back, withMesh)
	if !bytes.Equal(back, data) {
		t.Error("round-trip с размешиванием не сошёлся")
	}
}
