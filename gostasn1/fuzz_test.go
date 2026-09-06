// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"bytes"
	"crypto/x509"
	"testing"
)

// FuzzParsePublicKey: разбор ключа из чужого сертификата не должен падать
// ни на каком вводе, а успешно разобранный ключ обязан кодироваться
// обратно в тот же самый DER.
func FuzzParsePublicKey(f *testing.F) {
	for _, pem := range []string{certD2, certD3} {
		cert, err := x509.ParseCertificate(mustDER(f, pem))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(cert.RawSubjectPublicKeyInfo)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		pub, err := ParsePublicKey(der)
		if err != nil {
			return
		}
		// Точка обязана лежать на кривой: разбор не должен пропускать
		// ключи, с которыми проверка подписи ведёт себя непредсказуемо.
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			t.Fatal("разобран ключ, точка которого не лежит на кривой")
		}
		out, err := MarshalPublicKey(pub)
		if err != nil {
			t.Fatalf("обратное кодирование: %v", err)
		}
		if !bytes.Equal(out, der) {
			t.Fatalf("кодирование не совпало с исходным DER\n  было  %x\n  стало %x", der, out)
		}
	})
}

// FuzzSignatureHalves: перестановка половин обратима и не портит длину.
func FuzzSignatureHalves(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x01}, 64))
	f.Add(bytes.Repeat([]byte{0x02}, 128))
	f.Add([]byte{0x03})

	f.Fuzz(func(t *testing.T, sig []byte) {
		pkix, err := SignatureToPKIX(sig)
		if err != nil {
			return
		}
		if len(pkix) != len(sig) {
			t.Fatalf("длина изменилась: %d вместо %d", len(pkix), len(sig))
		}
		back, err := SignatureFromPKIX(pkix)
		if err != nil {
			t.Fatalf("обратное преобразование: %v", err)
		}
		if !bytes.Equal(back, sig) {
			t.Fatal("перестановка половин необратима")
		}
	})
}

// FuzzParseCertificate: сертификат приходит из недоверенного источника,
// поэтому извлечение ключа и проверка подписи обязаны быть устойчивы.
func FuzzParseCertificate(f *testing.F) {
	for _, pem := range []string{certD2, certD3} {
		f.Add(mustDER(f, pem))
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		pub, err := PublicKeyFromCertificate(cert)
		if err != nil {
			return
		}
		_ = CheckCertificateSignature(cert, pub)
	})
}
