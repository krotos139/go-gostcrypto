// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pfx

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/krotos139/go-gostcrypto/gostasn1"
)

func unb64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, s))
	if err != nil {
		t.Fatalf("некорректный base64: %v", err)
	}
	return b
}

// Основной опыт: разобрать контейнер из стандарта и убедиться, что ключ
// и сертификат из него составляют пару.
func TestRecommendation50112Container(t *testing.T) {
	der := unb64(t, exampleContainerB64)

	c, err := Parse(der, []byte(examplePassword))
	if err != nil {
		t.Fatalf("контейнер не разобрался: %v", err)
	}
	if !c.HasMAC {
		t.Error("имитовставка не проверена")
	}
	if c.SkippedSections != 0 {
		t.Errorf("пропущено разделов: %d", c.SkippedSections)
	}
	if len(c.Keys) != 1 {
		t.Fatalf("ключей: %d, ожидался один", len(c.Keys))
	}
	if len(c.Certificates) != 1 {
		t.Fatalf("сертификатов: %d, ожидался один", len(c.Certificates))
	}
	if !c.Keys[0].Encrypted {
		t.Error("ключ ожидался в зашифрованном портфеле")
	}

	// Ключ обязан соответствовать сертификату из того же контейнера.
	pub, err := gostasn1.PublicKeyFromCertificate(c.Certificates[0].Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Keys[0].Key.PublicKey.Equal(pub) {
		t.Fatal("ключ не соответствует сертификату из контейнера")
	}

	// И совпадать с сертификатом, приведённым в стандарте отдельно.
	want, err := x509.ParseCertificate(unb64(t, exampleCertB64))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Certificates[0].Certificate.Raw, want.Raw) {
		t.Error("сертификат в контейнере отличается от приведённого в стандарте")
	}

	// Ключ и сертификат связаны меткой localKeyId.
	if len(c.Keys[0].LocalKeyID) == 0 {
		t.Error("у ключа нет метки localKeyId")
	}
	if got := c.CertificateFor(c.Keys[0]); got == nil {
		t.Error("сертификат для ключа не найден")
	} else if !bytes.Equal(got.Raw, want.Raw) {
		t.Error("CertificateFor вернул не тот сертификат")
	}
}

func TestDecodeExample(t *testing.T) {
	priv, cert, err := Decode(unb64(t, exampleContainerB64), []byte(examplePassword))
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil || cert == nil {
		t.Fatal("Decode вернул неполную пару")
	}
	if cert.Subject.CommonName != "Test certificate 1 (PKCS#12 example)" {
		t.Errorf("сертификат: %q", cert.Subject.CommonName)
	}
	if priv.Curve.Name() != "id-tc26-gost-3410-2012-256-paramSetB" {
		t.Errorf("кривая: %s", priv.Curve.Name())
	}
}

// Целостность обязана проверяться: неверный пароль ловится имитовставкой
// раньше, чем дело дойдёт до расшифрования ключа.
func TestWrongPassword(t *testing.T) {
	der := unb64(t, exampleContainerB64)
	for _, p := range []string{"", "пароль для PFX", "Пароль для PFX ", "x"} {
		if _, err := Parse(der, []byte(p)); err != ErrMAC {
			t.Errorf("пароль %q: err = %v", p, err)
		}
	}
}

// Изменение любого байта содержимого обязано ломать имитовставку.
func TestTamperedContainer(t *testing.T) {
	der := unb64(t, exampleContainerB64)
	// Портим байт внутри зашифрованного раздела: он покрыт
	// имитовставкой, значит проверка обязана сработать.
	for _, pos := range []int{100, 500, 900, 1200} {
		bad := append([]byte(nil), der...)
		bad[pos] ^= 0x01
		if _, err := Parse(bad, []byte(examplePassword)); err == nil {
			t.Errorf("байт %d: испорченный контейнер принят", pos)
		}
	}
	// И порча самой имитовставки тоже.
	bad := append([]byte(nil), der...)
	bad[len(bad)-40] ^= 0x01
	if _, err := Parse(bad, []byte(examplePassword)); err == nil {
		t.Error("испорченная имитовставка принята")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(nil, nil); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}
	der := unb64(t, exampleContainerB64)
	for n := 1; n < len(der); n += 37 {
		if _, err := Parse(der[:n], []byte(examplePassword)); err == nil {
			t.Fatalf("обрезка до %d байт принята", n)
		}
	}
}

// FuzzParse: контейнер приходит извне.
func FuzzParse(f *testing.F) {
	f.Add(unb64(f, exampleContainerB64), []byte(examplePassword))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x30, 0x00}, []byte("p"))

	f.Fuzz(func(t *testing.T, der, password []byte) {
		c, err := Parse(der, password)
		if err != nil {
			return
		}
		for _, k := range c.Keys {
			if !k.Key.Curve.IsOnCurve(k.Key.PublicKey.X, k.Key.PublicKey.Y) {
				t.Fatal("ключ не лежит на кривой")
			}
		}
	})
}

func BenchmarkParse(b *testing.B) {
	der := unb64(b, exampleContainerB64)
	pass := []byte(examplePassword)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(der, pass); err != nil {
			b.Fatal(err)
		}
	}
}
