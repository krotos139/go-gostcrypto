// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pfx

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/pkcs8"
)

// Контрольного примера для защиты ключом отправителя в рекомендациях
// нет, поэтому здесь проверяется сходимость с самой собой и соответствие
// требованиям текста: разделы зашифрованы, macData отсутствует,
// целостность подтверждена подписью.

func TestKeyProtectedRoundTrip(t *testing.T) {
	for _, c := range curves {
		t.Run(c.Name(), func(t *testing.T) {
			priv, cert := newPair(t, c, "передаваемый ключ", 1)
			recipKey, recipCert := newPair(t, c, "получатель", 2)
			senderKey, senderCert := newPair(t, c, "отправитель", 3)

			der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
				[]*x509.Certificate{recipCert},
				&Sender{Key: senderKey, Certificate: senderCert}, nil)
			if err != nil {
				t.Fatal(err)
			}

			got, gotCert, err := DecodeWithKey(der, &Recipient{Key: recipKey, Certificate: recipCert})
			if err != nil {
				t.Fatal(err)
			}
			if got.D.Cmp(priv.D) != 0 {
				t.Fatal("ключ не совпал")
			}
			if gotCert == nil || !bytes.Equal(gotCert.Raw, cert.Raw) {
				t.Fatal("сертификат не совпал")
			}

			cont, err := ParseWithKey(der, &Recipient{Key: recipKey, Certificate: recipCert})
			if err != nil {
				t.Fatal(err)
			}
			if cont.HasMAC {
				t.Error("имитовставки здесь быть не должно")
			}
			if len(cont.Signers) != 1 {
				t.Fatalf("подписантов: %d, ожидался один", len(cont.Signers))
			}
			if !bytes.Equal(cont.Signers[0].Raw, senderCert.Raw) {
				t.Error("подписантом оказался не отправитель")
			}
			if cont.SkippedSections != 0 {
				t.Errorf("пропущено разделов: %d", cont.SkippedSections)
			}
		})
	}
}

// Требования п. 7 рекомендаций: authSafe — подписанное сообщение,
// macData отсутствует.
func TestKeyProtectedStructure(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	_, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)

	der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{recipCert},
		&Sender{Key: senderKey, Certificate: senderCert}, nil)
	if err != nil {
		t.Fatal(err)
	}

	p, err := parseHeader(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.MacData.Mac.Digest) != 0 {
		t.Error("macData присутствует, хотя целостность подтверждена подписью")
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(p.AuthSafe.FullBytes, &ci); err != nil {
		t.Fatal(err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Errorf("тип authSafe = %v, ожидался signedData", ci.ContentType)
	}

	// Ни ключ, ни сертификат не должны быть видны в открытом виде.
	raw := make([]byte, 32)
	priv.D.FillBytes(raw)
	if bytes.Contains(der, raw) {
		t.Error("ключ виден в контейнере")
	}
	if bytes.Contains(der, cert.Raw) {
		t.Error("сертификат виден в контейнере")
	}
}

// Чужой ключ получателя не должен раскрывать контейнер.
func TestKeyProtectedRejectsWrongRecipient(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	_, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)
	otherKey, otherCert := newPair(t, c, "посторонний", 4)

	der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{recipCert},
		&Sender{Key: senderKey, Certificate: senderCert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseWithKey(der, &Recipient{Key: otherKey, Certificate: otherCert}); err == nil {
		t.Error("посторонний получатель раскрыл контейнер")
	}
}

// Порча обязана ловиться подписью отправителя.
func TestKeyProtectedDetectsTampering(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	recipKey, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)

	der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{recipCert},
		&Sender{Key: senderKey, Certificate: senderCert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	to := &Recipient{Key: recipKey, Certificate: recipCert}
	if _, err := ParseWithKey(der, to); err != nil {
		t.Fatalf("целый контейнер: %v", err)
	}
	for _, pos := range []int{100, len(der) / 2, len(der) - 100} {
		bad := append([]byte(nil), der...)
		bad[pos] ^= 0x01
		if _, err := ParseWithKey(bad, to); err == nil {
			t.Errorf("байт %d: испорченный контейнер принят", pos)
		}
	}
}

// Несколько получателей: каждый раскрывает контейнер своим ключом.
func TestKeyProtectedManyRecipients(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	aKey, aCert := newPair(t, c, "первый", 2)
	bKey, bCert := newPair(t, c, "второй", 3)
	senderKey, senderCert := newPair(t, c, "отправитель", 4)

	der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{aCert, bCert},
		&Sender{Key: senderKey, Certificate: senderCert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range []*Recipient{
		{Key: aKey, Certificate: aCert},
		{Key: bKey, Certificate: bCert},
	} {
		got, _, err := DecodeWithKey(der, r)
		if err != nil {
			t.Fatalf("получатель %d: %v", i, err)
		}
		if got.D.Cmp(priv.D) != 0 {
			t.Fatalf("получатель %d: ключ не совпал", i)
		}
	}
}

// Два способа защиты не должны путаться: каждый разбор берётся только за
// свой вид контейнера.
func TestProtectionMethodsAreDistinct(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	recipKey, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)
	password := []byte("пароль")

	byPassword, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	byKey, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{recipCert},
		&Sender{Key: senderKey, Certificate: senderCert}, nil)
	if err != nil {
		t.Fatal(err)
	}

	to := &Recipient{Key: recipKey, Certificate: recipCert}
	if _, err := ParseWithKey(byPassword, to); err != ErrUnsupported {
		t.Errorf("парольный контейнер через ParseWithKey: err = %v", err)
	}
	if _, err := Parse(byKey, password); err != ErrUnsupported {
		t.Errorf("контейнер на ключе через Parse: err = %v", err)
	}
}

func TestKeyProtectedOptions(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	recipKey, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)
	when := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{recipCert},
		&Sender{Key: senderKey, Certificate: senderCert},
		&MarshalOptions{
			SigningTime: when,
			LocalKeyID:  []byte{9, 9, 9},
			KeyOptions:  &pkcs8.EncryptOptions{Marshal: &pkcs8.MarshalOptions{Masks: 2}},
		})
	if err != nil {
		t.Fatal(err)
	}
	cont, err := ParseWithKey(der, &Recipient{Key: recipKey, Certificate: recipCert})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cont.Keys[0].LocalKeyID, []byte{9, 9, 9}) {
		t.Errorf("метка = %x", cont.Keys[0].LocalKeyID)
	}
	if cont.Keys[0].Key.D.Cmp(priv.D) != 0 {
		t.Error("ключ не совпал")
	}
	// Маскирование не должно мешать разбору, но обязано прятать ключ.
	raw := make([]byte, 32)
	priv.D.FillBytes(raw)
	if bytes.Contains(der, raw) {
		t.Error("ключ виден в контейнере")
	}
}

// Открытые сертификаты допустимы и здесь: раздел остаётся незашифрованным.
func TestKeyProtectedPlainCertificates(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	recipKey, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)

	der, err := MarshalWithKey(rand.Reader, priv, []*x509.Certificate{cert},
		[]*x509.Certificate{recipCert},
		&Sender{Key: senderKey, Certificate: senderCert},
		&MarshalOptions{PlainCertificates: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(der, cert.Raw) {
		t.Error("при PlainCertificates сертификат обязан лежать открыто")
	}
	cont, err := ParseWithKey(der, &Recipient{Key: recipKey, Certificate: recipCert})
	if err != nil {
		t.Fatal(err)
	}
	if len(cont.Certificates) != 1 {
		t.Fatalf("сертификатов: %d", len(cont.Certificates))
	}
}

func TestKeyProtectedErrors(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "ключ", 1)
	_, recipCert := newPair(t, c, "получатель", 2)
	senderKey, senderCert := newPair(t, c, "отправитель", 3)
	sender := &Sender{Key: senderKey, Certificate: senderCert}
	certs := []*x509.Certificate{cert}
	to := []*x509.Certificate{recipCert}

	if _, err := MarshalWithKey(rand.Reader, nil, certs, to, sender, nil); err != ErrNoKey {
		t.Errorf("без ключа: err = %v", err)
	}
	if _, err := MarshalWithKey(rand.Reader, priv, certs, nil, sender, nil); err != ErrNoRecipients {
		t.Errorf("без получателей: err = %v", err)
	}
	if _, err := MarshalWithKey(rand.Reader, priv, certs, to, nil, nil); err != ErrNoSender {
		t.Errorf("без отправителя: err = %v", err)
	}
	if _, err := ParseWithKey(nil, nil); err != ErrNoKey {
		t.Errorf("без ключа получателя: err = %v", err)
	}
	if _, err := ParseWithKey(nil, &Recipient{Key: priv}); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}
}
