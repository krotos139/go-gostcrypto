// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3410"
)

// Запросы на сертификат из приложения D к RFC 9215: подпись под запросом
// ставится тем же ключом, на который он выписан, поэтому проверить её
// можно, не имея ничего кроме самого запроса.
func TestCertificateRequestsRFC9215(t *testing.T) {
	for i, pem := range []string{requestD1, requestD2, requestD3} {
		req, err := x509.ParseCertificateRequest(mustDER(t, pem))
		if err != nil {
			t.Fatalf("запрос %d не разбирается: %v", i+1, err)
		}
		pub, err := PublicKeyFromCertificateRequest(req)
		if err != nil {
			t.Fatalf("запрос %d: ключ не извлечён: %v", i+1, err)
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			t.Fatalf("запрос %d: точка не на кривой", i+1)
		}
		if err := CheckCertificateRequestSignature(req); err != nil {
			t.Fatalf("запрос %d: подпись не прошла: %v", i+1, err)
		}
	}
}

// Контрольный опыт: испорченная подпись обязана отвергаться, иначе
// проверка ничего не значит.
func TestCertificateRequestRejectsTampering(t *testing.T) {
	der := mustDER(t, requestD2)
	for _, pos := range []int{len(der) - 1, len(der) - 20, 60} {
		bad := append([]byte(nil), der...)
		bad[pos] ^= 0x01
		req, err := x509.ParseCertificateRequest(bad)
		if err != nil {
			continue // испорчена структура, до подписи не дошло
		}
		if err := CheckCertificateRequestSignature(req); err == nil {
			t.Errorf("байт %d: испорченный запрос принят", pos)
		}
	}
}

// Списки отзыва из того же приложения подписаны ключом центра, поэтому
// проверяются сертификатом из соседнего раздела.
func TestCRLsRFC9215(t *testing.T) {
	cases := []struct{ crl, cert string }{
		{crlD1, certD1},
		{crlD2, certD2},
		{crlD3, certD3},
	}
	for i, c := range cases {
		cert, err := x509.ParseCertificate(mustDER(t, c.cert))
		if err != nil {
			t.Fatalf("сертификат %d: %v", i+1, err)
		}
		pub, err := PublicKeyFromCertificate(cert)
		if err != nil {
			t.Fatalf("сертификат %d: %v", i+1, err)
		}
		crl := mustDER(t, c.crl)
		if err := CheckCRLSignature(crl, pub); err != nil {
			t.Fatalf("список отзыва %d: подпись не прошла: %v", i+1, err)
		}

		// Контрольный опыт.
		bad := append([]byte(nil), crl...)
		bad[len(bad)-1] ^= 0x01
		if err := CheckCRLSignature(bad, pub); err == nil {
			t.Errorf("список отзыва %d: испорченная подпись принята", i+1)
		}
		// И чужим ключом проверяться не должен.
		other, err := x509.ParseCertificate(mustDER(t, certD3))
		if err != nil {
			t.Fatal(err)
		}
		otherPub, err := PublicKeyFromCertificate(other)
		if err != nil {
			t.Fatal(err)
		}
		if i != 2 {
			if err := CheckCRLSignature(crl, otherPub); err == nil {
				t.Errorf("список отзыва %d: принят чужим ключом", i+1)
			}
		}
	}
}

func TestCreateCertificateRequest(t *testing.T) {
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
			subject := pkix.Name{
				CommonName: "Заявитель",
				Country:    []string{"RU"},
			}
			der, err := CreateCertificateRequest(rand.Reader, subject, priv)
			if err != nil {
				t.Fatal(err)
			}

			req, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatalf("собранный запрос не разбирается: %v", err)
			}
			if req.Subject.CommonName != "Заявитель" {
				t.Errorf("имя = %q", req.Subject.CommonName)
			}
			if err := CheckCertificateRequestSignature(req); err != nil {
				t.Fatalf("подпись под своим же запросом не прошла: %v", err)
			}

			// Ключ в запросе — тот самый.
			pub, err := PublicKeyFromCertificateRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			if !pub.Equal(&priv.PublicKey) {
				t.Error("в запросе не тот открытый ключ")
			}

			// Контрольный опыт: подмена ключа ломает подпись.
			bad := append([]byte(nil), der...)
			bad[len(bad)-1] ^= 0x01
			if req2, err := x509.ParseCertificateRequest(bad); err == nil {
				if err := CheckCertificateRequestSignature(req2); err == nil {
					t.Error("испорченный запрос принят")
				}
			}
		})
	}
}

func TestRequestAndCRLErrors(t *testing.T) {
	if err := CheckCRLSignature(nil, nil); err != ErrMalformed {
		t.Errorf("пустой список отзыва: err = %v", err)
	}
	if _, err := CreateCertificateRequest(rand.Reader, pkix.Name{}, nil); err != ErrMalformed {
		t.Errorf("без ключа: err = %v", err)
	}

	// Обрезка не должна приводить к панике.
	crl := mustDER(t, crlD2)
	cert, err := x509.ParseCertificate(mustDER(t, certD2))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n < len(crl); n += 7 {
		if err := CheckCRLSignature(crl[:n], pub); err == nil {
			t.Fatalf("обрезка до %d байт принята", n)
		}
	}
}

// Отечественные атрибуты имени обязаны получать сокращения, а не
// оставаться числами.
func TestAttributeNames(t *testing.T) {
	cases := []struct {
		oid  asn1.ObjectIdentifier
		want string
	}{
		{OIDOGRN, "OGRN"},
		{OIDSNILS, "SNILS"},
		{OIDINNLE, "INNLE"},
		{OIDOGRNIP, "OGRNIP"},
		{OIDINN, "INN"},
		{OIDIdentificationKind, "IdentificationKind"},
		{asn1.ObjectIdentifier{1, 2, 3}, ""},
	}
	for _, c := range cases {
		if got := AttributeName(c.oid); got != c.want {
			t.Errorf("AttributeName(%v) = %q, ожидалось %q", c.oid, got, c.want)
		}
	}

	// В имени с отечественными атрибутами они обязаны находиться.
	// Значения вымышленные: настоящим ИНН и СНИЛС в открытом
	// репозитории не место.
	name := pkix.Name{
		CommonName: "Пример",
		Names: []pkix.AttributeTypeAndValue{
			{Type: OIDINN, Value: "123456789012"},
			{Type: OIDSNILS, Value: "12345678901"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Пример"},
		},
	}
	attrs := Attributes(name)
	if attrs["INN"] != "123456789012" {
		t.Errorf("INN = %q", attrs["INN"])
	}
	if attrs["SNILS"] != "12345678901" {
		t.Errorf("SNILS = %q", attrs["SNILS"])
	}
	if len(attrs) != 2 {
		t.Errorf("атрибутов: %d, ожидалось два", len(attrs))
	}

	// FormatName подставляет сокращения вместо чисел.
	name.ExtraNames = name.Names
	if got := FormatName(name); got == "" {
		t.Error("FormatName вернул пустую строку")
	}
}

func BenchmarkCheckCertificateRequest(b *testing.B) {
	req, err := x509.ParseCertificateRequest(mustDER(b, requestD2))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := CheckCertificateRequestSignature(req); err != nil {
			b.Fatal(err)
		}
	}
}
