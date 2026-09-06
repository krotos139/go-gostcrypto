// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pfx

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
	"github.com/krotos139/go-gostcrypto/pkcs8"
)

type validity struct{ NotBefore, NotAfter time.Time }

// selfSigned собирает самоподписанный сертификат: crypto/x509 выпускать
// отечественные сертификаты не умеет, поэтому TBS собирается вручную.
func selfSigned(t testing.TB, priv *gost3410.PrivateKey, cn string, serial int64) *x509.Certificate {
	t.Helper()

	spki, err := gostasn1.MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	name, err := asn1.Marshal(pkix.Name{CommonName: cn, Country: []string{"RU"}}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	alg, err := asn1.Marshal(pkcs8.AlgorithmIdentifier{
		Algorithm: gostasn1.SignatureAlgorithmOID(priv.Curve),
	})
	if err != nil {
		t.Fatal(err)
	}
	serialDER, err := asn1.Marshal(big.NewInt(serial))
	if err != nil {
		t.Fatal(err)
	}
	val, err := asn1.Marshal(validity{
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := asn1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}

	tbs := concat(derWrap(0xA0, ver), serialDER, alg, name, val, name, spki)
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
	cert, err := x509.ParseCertificate(derWrap(0x30, concat(tbsDER, alg, sigDER)))
	if err != nil {
		t.Fatalf("собранный сертификат не разбирается: %v", err)
	}
	return cert
}

func newPair(t testing.TB, c *gost3410.Curve, cn string, serial int64) (*gost3410.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := gost3410.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, selfSigned(t, priv, cn, serial)
}

var curves = []*gost3410.Curve{
	gost3410.TC26ParamSet256A(),
	gost3410.TC26ParamSet256B(),
	gost3410.TC26ParamSet512A(),
	gost3410.TC26ParamSet512C(),
}

func TestMarshalRoundTrip(t *testing.T) {
	for _, c := range curves {
		t.Run(c.Name(), func(t *testing.T) {
			priv, cert := newPair(t, c, "владелец", 1)
			password := []byte("пароль контейнера")

			der, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password, nil)
			if err != nil {
				t.Fatal(err)
			}

			got, gotCert, err := Decode(der, password)
			if err != nil {
				t.Fatal(err)
			}
			if got.D.Cmp(priv.D) != 0 {
				t.Fatal("ключ не совпал")
			}
			if gotCert == nil || !bytes.Equal(gotCert.Raw, cert.Raw) {
				t.Fatal("сертификат не совпал")
			}

			cont, err := Parse(der, password)
			if err != nil {
				t.Fatal(err)
			}
			if !cont.HasMAC {
				t.Error("имитовставка не проверена")
			}
			if cont.SkippedSections != 0 {
				t.Errorf("пропущено разделов: %d", cont.SkippedSections)
			}
		})
	}
}

// Цепочка сертификатов кладётся целиком, а меткой связан только первый.
func TestMarshalChain(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, leaf := newPair(t, c, "владелец", 1)
	_, ca := newPair(t, c, "удостоверяющий центр", 2)
	_, root := newPair(t, c, "корень", 3)
	password := []byte("p")

	der, err := Marshal(rand.Reader, priv, []*x509.Certificate{leaf, ca, root}, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	cont, err := Parse(der, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(cont.Certificates) != 3 {
		t.Fatalf("сертификатов: %d, ожидалось три", len(cont.Certificates))
	}
	if got := cont.CertificateFor(cont.Keys[0]); got == nil || !bytes.Equal(got.Raw, leaf.Raw) {
		t.Error("парным ключу оказался не тот сертификат")
	}
	// Метка есть только у первого.
	var labelled int
	for _, ce := range cont.Certificates {
		if len(ce.LocalKeyID) > 0 {
			labelled++
		}
	}
	if labelled != 1 {
		t.Errorf("сертификатов с меткой: %d, ожидался один", labelled)
	}
}

// Сертификаты по умолчанию шифруются: п. 4.2 рекомендаций объясняет
// зачем — по сертификату видно владельца ключа.
func TestCertificatesEncryptedByDefault(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "тайный владелец", 1)
	password := []byte("p")

	enc, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, cert.Raw) {
		t.Error("сертификат лежит в контейнере открыто")
	}

	plain, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password,
		&MarshalOptions{PlainCertificates: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, cert.Raw) {
		t.Error("при PlainCertificates сертификат обязан лежать открыто")
	}
	// И тот и другой обязаны читаться.
	for _, der := range [][]byte{enc, plain} {
		cont, err := Parse(der, password)
		if err != nil {
			t.Fatal(err)
		}
		if len(cont.Certificates) != 1 {
			t.Fatalf("сертификатов: %d", len(cont.Certificates))
		}
	}
}

// Разделы обязаны шифроваться на разных солях: иначе один и тот же ключ
// шифровал бы весь контейнер (п. 4.2 рекомендаций).
func TestSectionsUseDifferentSalts(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "владелец", 1)

	der, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, []byte("p"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Собираем все соли PBKDF2 из контейнера: они идут после
	// идентификатора алгоритма и имеют длину 32 байта.
	var p pfxASN1
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		t.Fatal(err)
	}
	salts := findSalts(t, der)
	// Две: одна на портфель с ключом, одна на раздел с сертификатами.
	if len(salts) < 2 {
		t.Fatalf("найдено солей: %d, ожидалось не менее двух", len(salts))
	}
	seen := make(map[string]bool)
	for i, s := range salts {
		if seen[string(s)] {
			t.Errorf("соль %d повторяется", i)
		}
		seen[string(s)] = true
	}
}

// findSalts вытаскивает соли: каждая идёт сразу за OID PBKDF2 внутри
// SEQUENCE параметров.
func findSalts(t testing.TB, der []byte) [][]byte {
	t.Helper()
	pbkdf2OID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12})
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for i := 0; i+len(pbkdf2OID) < len(der); i++ {
		if !bytes.Equal(der[i:i+len(pbkdf2OID)], pbkdf2OID) {
			continue
		}
		rest := der[i+len(pbkdf2OID):]
		// SEQUENCE параметров, затем OCTET STRING соли.
		if len(rest) < 4 || rest[0] != 0x30 {
			continue
		}
		body := rest[2:]
		if len(body) < 2 || body[0] != 0x04 {
			continue
		}
		n := int(body[1])
		if len(body) < 2+n {
			continue
		}
		out = append(out, body[2:2+n])
	}
	return out
}

func TestMarshalOptions(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "владелец", 1)
	password := []byte("p")

	// Маскирование ключа внутри контейнера.
	der, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password, &MarshalOptions{
		Iterations: 500,
		KeyOptions: &pkcs8.EncryptOptions{
			Iterations: 500,
			Marshal:    &pkcs8.MarshalOptions{Masks: 3},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Decode(der, password)
	if err != nil {
		t.Fatal(err)
	}
	if got.D.Cmp(priv.D) != 0 {
		t.Fatal("ключ не совпал")
	}
	// Значение ключа не должно быть видно.
	raw := make([]byte, 32)
	priv.D.FillBytes(raw)
	if bytes.Contains(der, raw) {
		t.Error("ключ виден в контейнере")
	}

	// Своя метка связывания.
	id := []byte{1, 2, 3, 4}
	der, err = Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password,
		&MarshalOptions{LocalKeyID: id})
	if err != nil {
		t.Fatal(err)
	}
	cont, err := Parse(der, password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cont.Keys[0].LocalKeyID, id) {
		t.Errorf("метка ключа = %x, ожидалось %x", cont.Keys[0].LocalKeyID, id)
	}
}

// Контейнер без сертификатов допустим.
func TestMarshalKeyOnly(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, _ := newPair(t, c, "владелец", 1)
	password := []byte("p")

	der, err := Marshal(rand.Reader, priv, nil, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, cert, err := Decode(der, password)
	if err != nil {
		t.Fatal(err)
	}
	if got.D.Cmp(priv.D) != 0 {
		t.Fatal("ключ не совпал")
	}
	if cert != nil {
		t.Error("сертификат взялся из ниоткуда")
	}
}

// Собранный контейнер обязан отвергать чужой пароль и порчу.
func TestMarshalledContainerIsProtected(t *testing.T) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(t, c, "владелец", 1)
	password := []byte("правильный пароль")

	der, err := Marshal(rand.Reader, priv, []*x509.Certificate{cert}, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(der, []byte("неправильный пароль")); err != ErrMAC {
		t.Errorf("чужой пароль: err = %v", err)
	}
	for _, pos := range []int{50, len(der) / 2, len(der) - 50} {
		bad := append([]byte(nil), der...)
		bad[pos] ^= 0x01
		if _, err := Parse(bad, password); err == nil {
			t.Errorf("байт %d: испорченный контейнер принят", pos)
		}
	}
}

func TestMarshalErrors(t *testing.T) {
	if _, err := Marshal(rand.Reader, nil, nil, nil, nil); err != ErrNoKey {
		t.Errorf("без ключа: err = %v", err)
	}
}

func BenchmarkMarshal(b *testing.B) {
	c := gost3410.TC26ParamSet256B()
	priv, cert := newPair(b, c, "bench", 1)
	certs := []*x509.Certificate{cert}
	password := []byte("p")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Marshal(rand.Reader, priv, certs, password, nil); err != nil {
			b.Fatal(err)
		}
	}
}
