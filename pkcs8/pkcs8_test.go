// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pkcs8

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3410"
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

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex: %v", err)
	}
	return b
}

// Контрольный пример из приложения А к Р 50.1.112-2016.
//
// Приведён там в виде контейнера PKCS#12 на пароле «Пароль для PFX»;
// здесь взята из него структура EncryptedPrivateKeyInfo портфеля
// pkcs8ShroudedKeyBag и тестовый сертификат, которому этот ключ
// соответствует. Открытым текстом закрытый ключ в рекомендациях не
// приведён, поэтому проверка сквозная: расшифрованный ключ обязан дать
// открытый ключ из сертификата.
const (
	pfxPassword = "Пароль для PFX"

	encryptedKeyHex = "3081DD307106092A864886F70D01050D3064304106092A864886F70D01050C30" +
		"340420F9A99AF44D322C06F760528ABFCC5C0ECDDC89A218FAFF85A2C9C7208F" +
		"D00AFD020207D0300C06082A850307010104020500301F06062A850302021530" +
		"150408DC8A7F569D08B32206092A8503070102050101046849F2E1831F6CFF39" +
		"FE0639E14F4AE8AF4EEF4B9E58B39860BD5A560F1E265C6596C9ECFFDAC31C68" +
		"5812AF81F8513186C283329C62E917520E568F9B189D1E3EA1C1FA04B938BF68" +
		"57E3D4999FC42EB44434A9420EA7D85AFA52CACB57DBD0AF085AE74E70EC6C16"

	testCertB64 = `MIIDAjCCAq2gAwIBAgIQAdBoXzEflsAAAAALJwkAATAMBggqhQMHAQEDAgUAMGAx
CzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxDzANBgNVBAoMBtCi
0JoyNjEpMCcGA1UEAwwgQ0EgY2VydGlmaWNhdGUgKFBLQ1MjMTIgZXhhbXBsZSkw
HhcNMTUwMzI3MDcyNTAwWhcNMjAwMzI3MDcyMzAwWjBkMQswCQYDVQQGEwJSVTEV
MBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxLTArBgNVBAMM
JFRlc3QgY2VydGlmaWNhdGUgMSAoUEtDUyMxMiBleGFtcGxlKTBmMB8GCCqFAwcB
AQEBMBMGByqFAwICIwEGCCqFAwcBAQICA0MABEDXHPKaSm+vZ1glPxZM5fcO33r/
6Eaxc3K1RCmRYHkiYkzi2D0CwLhEhTBXkfjUyEbS4FEXB5PM3oCwB0G+FMKVgQkA
MjcwOTAwMDGjggEpMIIBJTArBgNVHRAEJDAigA8yMDE1MDMyNzA3MjUwMFqBDzIw
MTYwMzI3MDcyNTAwWjAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0OBBYEFCFY6xFDrzJg
3ZS2D+jAehZyqxVtMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAMBgNV
HRMBAf8EAjAAMIGZBgNVHSMEgZEwgY6AFCadzteHnKRvm38EzA6TEDh2t8SaoWSk
YjBgMQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQK
DAbQotCaMjYxKTAnBgNVBAMMIENBIGNlcnRpZmljYXRlIChQS0NTIzEyIGV4YW1w
bGUpghAB0Ghe8vxNIAAAAAsnCQABMAwGCCqFAwcBAQMCBQADQQD2irRW+TySSAjC
SnTHQnl4q2Jrgw1OLAoCbuOCcJkjHc73wFOFpNfdlCESjZEv2lMI+vrAUyF54n5h
0YxF5e+y`
)

// Основной опыт: расшифровать ключ из контрольного примера и убедиться,
// что он соответствует тестовому сертификату.
func TestRecommendation50112Example(t *testing.T) {
	der := unhex(t, encryptedKeyHex)

	priv, err := ParseEncryptedPrivateKey(der, []byte(pfxPassword))
	if err != nil {
		t.Fatalf("ключ не расшифровался: %v", err)
	}

	cert, err := x509.ParseCertificate(unb64(t, testCertB64))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gostasn1.PublicKeyFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Fatalf("открытый ключ не совпал с сертификатом\n  из ключа      X=%x\n  в сертификате X=%x",
			priv.PublicKey.X, pub.X)
	}
	if priv.Curve.Name() != "id-tc26-gost-3410-2012-256-paramSetB" {
		t.Errorf("кривая: %s", priv.Curve.Name())
	}

	// Ключ в примере замаскирован: поле privateKey вдвое длиннее ключа.
	plain, err := DecryptPrivateKeyInfo(der, []byte(pfxPassword))
	if err != nil {
		t.Fatal(err)
	}
	var info privateKeyInfo
	if _, err := asn1.Unmarshal(plain, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.PrivateKey) != 2*priv.Curve.Size() {
		t.Errorf("длина поля ключа %d, ожидалось %d (KM и одна маска)",
			len(info.PrivateKey), 2*priv.Curve.Size())
	}
}

// Неверный пароль не должен давать ключ.
func TestWrongPassword(t *testing.T) {
	der := unhex(t, encryptedKeyHex)
	for _, p := range []string{"", "Пароль для PFX ", "пароль для PFX", "wrong"} {
		if _, err := ParseEncryptedPrivateKey(der, []byte(p)); err == nil {
			t.Errorf("пароль %q принят", p)
		}
	}
}

func TestPlainRoundTrip(t *testing.T) {
	for _, c := range []*gost3410.Curve{
		gost3410.TC26ParamSet256A(),
		gost3410.TC26ParamSet256B(),
		gost3410.TC26ParamSet512A(),
		gost3410.TC26ParamSet512C(),
	} {
		t.Run(c.Name(), func(t *testing.T) {
			priv, err := gost3410.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			// И без масок, и с ними.
			for _, masks := range []int{0, 1, 2, 5} {
				der, err := MarshalPrivateKey(priv, &MarshalOptions{Masks: masks})
				if err != nil {
					t.Fatalf("масок %d: %v", masks, err)
				}
				back, err := ParsePrivateKey(der)
				if err != nil {
					t.Fatalf("масок %d: %v", masks, err)
				}
				if back.D.Cmp(priv.D) != 0 {
					t.Fatalf("масок %d: ключ не совпал", masks)
				}
				if !back.PublicKey.Equal(&priv.PublicKey) {
					t.Fatalf("масок %d: открытый ключ не совпал", masks)
				}
			}
		})
	}
}

// Маски обязаны прятать значение ключа: сам ключ в кодировке не виден,
// и два вызова дают разное представление.
func TestMasksHideKey(t *testing.T) {
	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	priv.D.FillBytes(raw)
	le := append([]byte(nil), raw...)
	for i, j := 0, len(le)-1; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}

	plain, err := MarshalPrivateKey(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, le) {
		t.Error("без масок ключ обязан лежать как есть")
	}

	a, err := MarshalPrivateKey(priv, &MarshalOptions{Masks: 1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(a, le) {
		t.Error("замаскированное представление содержит ключ в открытом виде")
	}
	b, err := MarshalPrivateKey(priv, &MarshalOptions{Masks: 1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("две маскировки дали одинаковый результат")
	}
}

func TestEncryptedRoundTrip(t *testing.T) {
	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("пароль с кириллицей и пробелом ")

	for _, opts := range []*EncryptOptions{
		nil,
		{Iterations: 1000, SaltSize: 8},
		{ParamSet: gostasn1.OIDCipherCryptoProA},
		{Marshal: &MarshalOptions{Masks: 2}},
	} {
		der, err := MarshalEncryptedPrivateKey(rand.Reader, priv, password, opts)
		if err != nil {
			t.Fatalf("%+v: %v", opts, err)
		}
		back, err := ParseEncryptedPrivateKey(der, password)
		if err != nil {
			t.Fatalf("%+v: %v", opts, err)
		}
		if back.D.Cmp(priv.D) != 0 {
			t.Fatalf("%+v: ключ не совпал", opts)
		}
		// Ключ не должен быть виден в шифртексте.
		raw := make([]byte, 32)
		priv.D.FillBytes(raw)
		if bytes.Contains(der, raw) {
			t.Errorf("%+v: ключ виден в зашифрованном представлении", opts)
		}
		if _, err := ParseEncryptedPrivateKey(der, []byte("другой пароль")); err == nil {
			t.Errorf("%+v: чужой пароль принят", opts)
		}
	}
}

// Длинный ключ пересекает границу ключевого размешивания только в
// контейнерах побольше, но проверить обратимость на разных длинах стоит.
func TestEncryptedLongPlaintext(t *testing.T) {
	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet512A(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("p")
	// Много масок делают кодировку длиннее 1024 байт.
	der, err := MarshalEncryptedPrivateKey(rand.Reader, priv, password, &EncryptOptions{
		Marshal: &MarshalOptions{Masks: 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(der) < 1024 {
		t.Fatalf("представление слишком короткое для проверки размешивания: %d байт", len(der))
	}
	back, err := ParseEncryptedPrivateKey(der, password)
	if err != nil {
		t.Fatal(err)
	}
	if back.D.Cmp(priv.D) != 0 {
		t.Fatal("ключ не совпал")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParsePrivateKey(nil); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}
	if _, err := ParseEncryptedPrivateKey(nil, nil); err != ErrMalformed {
		t.Errorf("пустой зашифрованный вход: err = %v", err)
	}

	// Обрезка не должна приводить к панике.
	der := unhex(t, encryptedKeyHex)
	for n := 1; n < len(der); n += 13 {
		if _, err := ParseEncryptedPrivateKey(der[:n], []byte(pfxPassword)); err == nil {
			t.Fatalf("обрезка до %d байт принята", n)
		}
	}

	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalPrivateKey(priv, &MarshalOptions{Masks: -1}); err != ErrMaskCount {
		t.Error("отрицательное число масок принято")
	}
	for _, n := range []int{1, 7, 33, 100} {
		if _, err := MarshalEncryptedPrivateKey(rand.Reader, priv, nil,
			&EncryptOptions{SaltSize: n}); err != ErrMalformed {
			t.Errorf("длина соли %d: err = %v", n, err)
		}
	}
	if _, err := MarshalEncryptedPrivateKey(rand.Reader, priv, nil,
		&EncryptOptions{Iterations: -1}); err != ErrIterations {
		t.Error("отрицательное число итераций принято")
	}
}

// FuzzParseEncrypted: зашифрованный ключ приходит извне.
func FuzzParseEncrypted(f *testing.F) {
	f.Add(unhex(f, encryptedKeyHex), []byte(pfxPassword))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x30, 0x00}, []byte("p"))

	f.Fuzz(func(t *testing.T, der, password []byte) {
		priv, err := ParseEncryptedPrivateKey(der, password)
		if err != nil {
			return
		}
		// Разобранный ключ обязан лежать на своей кривой.
		if !priv.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
			t.Fatal("открытый ключ не лежит на кривой")
		}
	})
}
