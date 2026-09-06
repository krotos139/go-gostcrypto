// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3410"
)

func mustInt(t testing.TB, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("некорректное число %q", s)
	}
	return v
}

func mustDER(t testing.TB, b64 string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b64, "\n", ""))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return der
}

// Сертификаты из RFC 9215, приложение D: подписаны независимой
// реализацией, поэтому проверяют всю цепочку соглашений сразу.
const (
	certD2 = "MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw" +
		"IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4" +
		"YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP" +
		"7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE" +
		"aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ" +
		"yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6" +
		"DglzGOeubudp"

	certD3 = "MIIBqjCCARagAwIBAgIBCzAKBggqhQMHAQEDAzASMRAwDgYDVQQDEwdFeGFtcGxl" +
		"MCAXDTAxMDEwMTAwMDAwMFoYDzIwNTAxMjMxMDAwMDAwWjASMRAwDgYDVQQDEwdF" +
		"eGFtcGxlMIGgMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAAOBhAAEgYDh7zDVLGEz" +
		"3dmdHVxBRVz3302LTJJbvGmvFDPRVlhRWt0hRoUMMlxbgcEzvmVaqMTUQOe5io1Z" +
		"SHsMdpa8xV0R7L53NqnsNX/y/TmTH04RTLjNo1knCsfw5/9D2UGUGeph/Sq3f12f" +
		"Y1I9O1CgT2PioM9Rt8E63CFWDwvUDMnHN6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAK" +
		"BggqhQMHAQEDAwOBgQBBVwPYkvGl8/aMQ1MYmn7iB7gLVjHvnUlSmk1rVCws+hWq" +
		"LqzxH0cP3n2VSFaQPDX9j5Ve8wDZXHdTSnJKDu5wL4b6YKCBCRoj3XleHjxonuUS" +
		"o8gu4NzCZDx47qj8rNNUklWEhrIPHJ7Bl8kGmYUCYMk7y82cXDMX4ZNE4XOuNg=="
)

func TestCertificates(t *testing.T) {
	cases := []struct {
		name    string
		pem     string
		curve   *gost3410.Curve
		x, y    string
		algOID  asn1.ObjectIdentifier
		paramID asn1.ObjectIdentifier
	}{
		{
			name:    "256 бит, tc26-256-A",
			pem:     certD2,
			curve:   gost3410.TC26ParamSet256A(),
			x:       "99C3DF265EA59350640BA69D1DE04418AF3FEA03EC0F85F2DD84E8BED4952774",
			y:       "E218631A69C47C122E2D516DA1C09E6BD19344D94389D1F16C0C4D4DCF96F578",
			algOID:  OIDPublicKey256,
			paramID: OIDParamSet256A,
		},
		{
			name:  "512 бит, тестовая кривая",
			pem:   certD3,
			curve: gost3410.TestParamSet512(),
			x: "115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD" +
				"5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1",
			y: "37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61" +
				"EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC",
			algOID:  OIDPublicKey512,
			paramID: OIDParamSet512Test,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := x509.ParseCertificate(mustDER(t, tc.pem))
			if err != nil {
				t.Fatalf("crypto/x509 не разобрал сертификат: %v", err)
			}
			// crypto/x509 не знает отечественных алгоритмов и оставляет
			// разобранный ключ пустым — это ожидаемо.
			if cert.PublicKey != nil {
				t.Log("внимание: crypto/x509 неожиданно разобрал ключ")
			}

			pub, err := PublicKeyFromCertificate(cert)
			if err != nil {
				t.Fatalf("разбор ключа: %v", err)
			}
			if pub.Curve != tc.curve {
				t.Fatalf("кривая %s, ожидалась %s", pub.Curve.Name(), tc.curve.Name())
			}
			if pub.X.Cmp(mustInt(t, tc.x)) != 0 || pub.Y.Cmp(mustInt(t, tc.y)) != 0 {
				t.Fatalf("координаты разобраны неверно:\n  (%x,\n   %x)", pub.X, pub.Y)
			}

			if err := CheckCertificateSignature(cert, pub); err != nil {
				t.Fatalf("проверка подписи: %v", err)
			}

			// Изменение подписанной части должно ломать проверку.
			bad := append([]byte(nil), cert.Raw...)
			bad[len(bad)-1] ^= 0x01
			badCert, err := x509.ParseCertificate(bad)
			if err == nil {
				if err := CheckCertificateSignature(badCert, pub); err == nil {
					t.Fatal("подпись принята для изменённого сертификата")
				}
			}

			// Перекодировка ключа должна давать исходные байты.
			der, err := MarshalPublicKey(pub)
			if err != nil {
				t.Fatalf("кодирование ключа: %v", err)
			}
			if !bytes.Equal(der, cert.RawSubjectPublicKeyInfo) {
				t.Errorf("перекодированный SPKI отличается:\n  %x\n  %x",
					der, cert.RawSubjectPublicKeyInfo)
			}
		})
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	for _, c := range gost3410.AllCurves() {
		t.Run(c.Name(), func(t *testing.T) {
			if _, ok := OIDByCurve(c); !ok {
				t.Skip("для кривой нет идентификатора")
			}
			priv, err := gost3410.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := MarshalPublicKey(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParsePublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			if !back.Equal(&priv.PublicKey) {
				t.Fatal("ключ не совпал после перекодировки")
			}
		})
	}
}

// Координаты в PKIX записаны от младшего байта к старшему — в отличие от
// r и s подписи. Тест фиксирует это явно.
func TestPublicKeyIsLittleEndian(t *testing.T) {
	cert, err := x509.ParseCertificate(mustDER(t, certD2))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}

	// Первые 32 байта содержимого — это x, записанный задом наперёд.
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if _, err := asn1.Unmarshal(spki.PublicKey.RightAlign(), &raw); err != nil {
		t.Fatal(err)
	}

	be := make([]byte, 32)
	pub.X.FillBytes(be)
	le := append([]byte(nil), raw[:32]...)
	reverse(le)
	if !bytes.Equal(be, le) {
		t.Fatalf("x в записи = %x\n  ожидался разворот %x", raw[:32], be)
	}
	if bytes.Equal(be, raw[:32]) {
		t.Fatal("координата оказалась big-endian — тест не различает порядки")
	}
}

// PKIX меняет половины подписи местами относительно самого стандарта.
func TestSignatureHalfSwap(t *testing.T) {
	sig, err := hex.DecodeString("1122334455667788" + "99aabbccddeeff00")
	if err != nil {
		t.Fatal(err)
	}
	pkixSig, err := SignatureToPKIX(sig)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pkixSig); got != "99aabbccddeeff001122334455667788" {
		t.Fatalf("SignatureToPKIX = %s", got)
	}
	back, err := SignatureFromPKIX(pkixSig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, sig) {
		t.Fatal("двойная перестановка не вернула исходное значение")
	}
	for _, bad := range [][]byte{nil, {}, {1}, {1, 2, 3}} {
		if _, err := SignatureToPKIX(bad); err != ErrMalformed {
			t.Errorf("длина %d: err = %v", len(bad), err)
		}
	}
}

// Наборы CryptoPro и ТК 26 должны указывать на одни и те же кривые
// (RFC 9215, приложение C).
func TestParamSetAliases(t *testing.T) {
	pairs := []struct {
		tc26, cryptoPro asn1.ObjectIdentifier
	}{
		{OIDParamSet256B, OIDParamSetCryptoProA},
		{OIDParamSet256C, OIDParamSetCryptoProB},
		{OIDParamSet256D, OIDParamSetCryptoProC},
	}
	for _, p := range pairs {
		a, ok1 := CurveByOID(p.tc26)
		b, ok2 := CurveByOID(p.cryptoPro)
		if !ok1 || !ok2 {
			t.Fatalf("%v / %v: набор не найден", p.tc26, p.cryptoPro)
		}
		if a != b {
			t.Errorf("%v и %v указывают на разные кривые", p.tc26, p.cryptoPro)
		}
	}
	// Наборы обмена задают те же кривые, что CryptoPro-A и CryptoPro-C.
	if a, _ := CurveByOID(OIDParamSetCryptoProXchA); a != gost3410.TC26ParamSet256B() {
		t.Error("XchA указывает не на ту кривую")
	}
	if a, _ := CurveByOID(OIDParamSetCryptoProXchB); a != gost3410.TC26ParamSet256D() {
		t.Error("XchB указывает не на ту кривую")
	}
}

// digestParamSet обязателен для наборов, унаследованных от
// ГОСТ Р 34.10-2001, и не должен появляться для остальных.
func TestDigestParamSetRule(t *testing.T) {
	for _, oid := range []asn1.ObjectIdentifier{
		OIDParamSetCryptoProA, OIDParamSetCryptoProB,
		OIDParamSetCryptoProC, OIDParamSetCryptoProTest,
	} {
		if !needsDigestParamSet(oid) {
			t.Errorf("%v: digestParamSet должен требоваться", oid)
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{
		OIDParamSet256A, OIDParamSet256B, OIDParamSet512A, OIDParamSet512Test,
	} {
		if needsDigestParamSet(oid) {
			t.Errorf("%v: digestParamSet не должен требоваться", oid)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParsePublicKey(nil); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}
	if _, err := ParsePublicKey([]byte{0x30, 0x00}); err != ErrMalformed {
		t.Errorf("пустая последовательность: err = %v", err)
	}
	// SPKI со знакомой структурой, но чужим алгоритмом.
	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		t.Fatal(err)
	}
	spki.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	other, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey(other); err != ErrUnsupportedAlgorithm {
		t.Errorf("чужой алгоритм: err = %v", err)
	}
}

func TestSignatureAlgorithmOID(t *testing.T) {
	if got := SignatureAlgorithmOID(gost3410.TC26ParamSet256B()); !got.Equal(OIDSignWithDigest256) {
		t.Errorf("для 256-битной кривой = %v", got)
	}
	if got := SignatureAlgorithmOID(gost3410.TC26ParamSet512A()); !got.Equal(OIDSignWithDigest512) {
		t.Errorf("для 512-битной кривой = %v", got)
	}
	if n := len(DigestForCurve(gost3410.TC26ParamSet256B(), nil)); n != 32 {
		t.Errorf("длина хэш-кода для 256 бит = %d", n)
	}
	if n := len(DigestForCurve(gost3410.TC26ParamSet512A(), nil)); n != 64 {
		t.Errorf("длина хэш-кода для 512 бит = %d", n)
	}
}
