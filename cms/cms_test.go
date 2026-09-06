// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
)

type validity struct {
	NotBefore, NotAfter time.Time
}

// selfSigned собирает самоподписанный сертификат с отечественным ключом.
//
// crypto/x509 не умеет выпускать такие сертификаты, поэтому TBSCertificate
// собирается вручную. Тестам нужна лишь пара «ключ + сертификат»,
// связанная подписью, а не полноценный удостоверяющий центр.
func selfSigned(t testing.TB, priv *gost3410.PrivateKey, cn string, serial int64) *x509.Certificate {
	t.Helper()

	spki, err := gostasn1.MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	name, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	algDER, err := asn1.Marshal(algorithmIdentifier{
		Algorithm: gostasn1.SignatureAlgorithmOID(priv.Curve),
	})
	if err != nil {
		t.Fatal(err)
	}
	serialDER, err := asn1.Marshal(big.NewInt(serial))
	if err != nil {
		t.Fatal(err)
	}
	validityDER, err := asn1.Marshal(validity{
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	versionDER, err := asn1.Marshal(2) // v3
	if err != nil {
		t.Fatal(err)
	}

	var tbs []byte
	tbs = append(tbs, derWrap(0xA0, versionDER)...)
	tbs = append(tbs, serialDER...)
	tbs = append(tbs, algDER...)
	tbs = append(tbs, name...) // issuer
	tbs = append(tbs, validityDER...)
	tbs = append(tbs, name...) // subject
	tbs = append(tbs, spki...)
	tbsDER := derWrap(0x30, tbs)

	sig, err := gost3410.Sign(rand.Reader, priv, gostasn1.DigestForCurve(priv.Curve, tbsDER))
	if err != nil {
		t.Fatal(err)
	}
	sigPKIX, err := gostasn1.SignatureToPKIX(sig)
	if err != nil {
		t.Fatal(err)
	}
	sigDER, err := asn1.Marshal(asn1.BitString{Bytes: sigPKIX, BitLength: len(sigPKIX) * 8})
	if err != nil {
		t.Fatal(err)
	}

	certDER := derWrap(0x30, append(append(append([]byte(nil), tbsDER...), algDER...), sigDER...))
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("собранный сертификат не разбирается: %v", err)
	}
	// Проверяем, что связка ключ-сертификат действительно согласована:
	// иначе тесты ниже проверяли бы не то, что нужно.
	pub, err := gostasn1.PublicKeyFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := gostasn1.CheckCertificateSignature(cert, pub); err != nil {
		t.Fatalf("самоподписанный сертификат не проверяется: %v", err)
	}
	return cert
}

func newSignerPair(t testing.TB, c *gost3410.Curve, cn string, serial int64) (*gost3410.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := gost3410.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, selfSigned(t, priv, cn, serial)
}

var curves = []struct {
	name  string
	curve *gost3410.Curve
}{
	{"256A", gost3410.TC26ParamSet256A()},
	{"256B", gost3410.TC26ParamSet256B()},
	{"512A", gost3410.TC26ParamSet512A()},
	{"512C", gost3410.TC26ParamSet512C()},
}

func TestSignVerifyDetached(t *testing.T) {
	content := []byte("документ, подписанный открепленной подписью")

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, cert := newSignerPair(t, tc.curve, "детач", 1)

			der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
			if err != nil {
				t.Fatal(err)
			}

			sd, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if !sd.Detached {
				t.Error("подпись должна быть открепленной")
			}
			if len(sd.Content) != 0 {
				t.Error("содержимое не должно быть встроено")
			}
			if len(sd.Signers) != 1 {
				t.Fatalf("подписантов: %d", len(sd.Signers))
			}
			if sd.Signers[0].Certificate == nil {
				t.Fatal("сертификат подписанта не найден")
			}
			if sd.Signers[0].Certificate.Subject.CommonName != "детач" {
				t.Errorf("не тот сертификат: %q", sd.Signers[0].Certificate.Subject.CommonName)
			}

			if err := sd.Verify(content); err != nil {
				t.Fatalf("подпись не прошла проверку: %v", err)
			}

			// Без содержимого проверить открепленную подпись нельзя.
			if err := sd.Verify(nil); err != ErrNoContent {
				t.Errorf("Verify(nil) = %v", err)
			}
		})
	}
}

func TestSignVerifyAttached(t *testing.T) {
	content := []byte("содержимое внутри сообщения")
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256B(), "встроенная", 2)

	der, err := Sign(rand.Reader, content, cert, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Detached {
		t.Error("подпись не должна быть открепленной")
	}
	if !bytes.Equal(sd.Content, content) {
		t.Fatalf("встроенное содержимое = %q", sd.Content)
	}
	if err := sd.Verify(nil); err != nil {
		t.Fatalf("подпись не прошла проверку: %v", err)
	}
}

func TestVerifyRejectsWrongContent(t *testing.T) {
	content := []byte("исходный документ")
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "подмена", 3)

	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}

	// Другой документ — расхождение ловится по messageDigest.
	if err := sd.Verify([]byte("подменённый документ")); err != ErrDigestMismatch {
		t.Errorf("подменённое содержимое: err = %v", err)
	}
	// Отличие в один байт тоже.
	bad := append([]byte(nil), content...)
	bad[0] ^= 0x01
	if err := sd.Verify(bad); err != ErrDigestMismatch {
		t.Errorf("испорченный байт: err = %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	content := []byte("подписанные данные")
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "порча", 4)

	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}

	// Порча самой подписи.
	sd.Signers[0].info.Signature[0] ^= 0x01
	if err := sd.Verify(content); err != ErrSignature {
		t.Errorf("испорченная подпись: err = %v", err)
	}
}

// Подпись, поставленная одним ключом, не должна проверяться сертификатом
// другого: иначе проверка ничего не значит.
func TestVerifyRejectsForeignCertificate(t *testing.T) {
	content := []byte("данные")
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "свой", 5)
	_, otherCert := newSignerPair(t, c, "чужой", 6)

	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	sd.Signers[0].Certificate = otherCert
	if err := sd.Verify(content); err != ErrSignature {
		t.Errorf("чужой сертификат: err = %v", err)
	}
}

func TestSignRejectsMismatchedCertificate(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, _ := newSignerPair(t, c, "ключ", 7)
	_, otherCert := newSignerPair(t, c, "чужой сертификат", 8)

	if _, err := Sign(rand.Reader, []byte("x"), otherCert, priv, nil); err != ErrKeyMismatch {
		t.Errorf("несоответствие ключа и сертификата: err = %v", err)
	}
}

func TestSigningTimeAttribute(t *testing.T) {
	content := []byte("с отметкой времени")
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet512A(), "время", 9)
	when := time.Date(2026, 9, 6, 12, 34, 56, 0, time.UTC)

	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true, SigningTime: when})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.Signers[0]
	if !s.HasSigningTime {
		t.Fatal("атрибут времени не разобран")
	}
	if !s.SigningTime.Equal(when) {
		t.Errorf("время = %v, ожидалось %v", s.SigningTime, when)
	}
	if err := sd.Verify(content); err != nil {
		t.Fatal(err)
	}

	// Без указания времени атрибута быть не должно.
	der, err = Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err = Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Signers[0].HasSigningTime {
		t.Error("атрибут времени появился без запроса")
	}
}

// Подписанные атрибуты кодируются как SET OF: по правилам DER их
// кодировки идут в порядке возрастания.
func TestSignedAttributesSorted(t *testing.T) {
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "порядок", 10)
	der, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{
		Detached:    true,
		SigningTime: time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	raw := sd.Signers[0].info.SignedAttrs
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 {
		t.Fatalf("атрибуты закодированы с тегом %d/%d", raw.Class, raw.Tag)
	}
	elems, err := derElements(raw.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// contentType, messageDigest, signingTime, signingCertificateV2
	if len(elems) != 4 {
		t.Fatalf("атрибутов: %d, ожидалось 4", len(elems))
	}
	for i := 1; i < len(elems); i++ {
		if bytes.Compare(elems[i-1], elems[i]) >= 0 {
			t.Errorf("атрибуты %d и %d не упорядочены", i-1, i)
		}
	}
}

// Подпись ставится над атрибутами с тегом SET, а хранятся они с неявным
// тегом [0]. Если перепутать, подпись не сойдётся ни у одного проверяющего.
func TestSignatureCoversSetEncoding(t *testing.T) {
	content := []byte("контроль тега")
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "тег", 11)
	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.Signers[0]
	pub, err := gostasn1.PublicKeyFromCertificate(s.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := gostasn1.SignatureFromPKIX(s.info.Signature)
	if err != nil {
		t.Fatal(err)
	}

	withSet := append([]byte(nil), s.info.SignedAttrs.FullBytes...)
	withSet[0] = 0x31
	if !gost3410.Verify(pub, gostasn1.DigestForCurve(pub.Curve, withSet), sig) {
		t.Error("подпись не сходится над представлением с тегом SET")
	}
	if gost3410.Verify(pub, gostasn1.DigestForCurve(pub.Curve, s.info.SignedAttrs.FullBytes), sig) {
		t.Error("подпись сошлась над представлением с тегом [0] — проверка не различает теги")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(nil); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}
	if _, err := Parse([]byte{0x30, 0x00}); err != ErrMalformed {
		t.Errorf("пустая последовательность: err = %v", err)
	}

	// ContentInfo с чужим типом содержимого.
	other, err := asn1.Marshal(contentInfo{ContentType: oidData})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(other); err != ErrUnsupported {
		t.Errorf("чужой тип содержимого: err = %v", err)
	}

	// Обрезанное сообщение не должно приводить к панике.
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "обрезка", 12)
	good, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n < len(good); n += 7 {
		if _, err := Parse(good[:n]); err == nil {
			t.Fatalf("обрезка до %d байт принята", n)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	priv, cert := newSignerPair(b, gost3410.TC26ParamSet256A(), "bench", 1)
	content := bytes.Repeat([]byte("a"), 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	priv, cert := newSignerPair(b, gost3410.TC26ParamSet256A(), "bench", 1)
	content := bytes.Repeat([]byte("a"), 4096)
	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sd, err := Parse(der)
		if err != nil {
			b.Fatal(err)
		}
		if err := sd.Verify(content); err != nil {
			b.Fatal(err)
		}
	}
}
