// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
)

// Подпись, сформированная библиотекой, должна нести ссылку на сертификат
// и проходить её проверку.
func TestSigningCertificatePresent(t *testing.T) {
	content := []byte("документ с ссылкой на сертификат")

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, cert := newSignerPair(t, tc.curve, "cades", 1)
			der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
			if err != nil {
				t.Fatal(err)
			}
			sd, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if !sd.Signers[0].HasSigningCertificate {
				t.Fatal("атрибут signingCertificateV2 не выставлен")
			}
			if err := sd.Verify(content); err != nil {
				t.Fatalf("проверка не прошла: %v", err)
			}
		})
	}
}

func TestSigningCertificateCanBeDisabled(t *testing.T) {
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "без атрибута", 2)
	der, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{
		Detached:             true,
		NoSigningCertificate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Signers[0].HasSigningCertificate {
		t.Error("атрибут выставлен вопреки запрету")
	}
	// Без атрибута подпись остаётся действительной — он необязателен на
	// уровне CMS, его требует лишь профиль CAdES.
	if err := sd.Verify([]byte("x")); err != nil {
		t.Fatalf("проверка не прошла: %v", err)
	}
}

// Главный смысл атрибута: он ловит перенос подписи к другому
// сертификату. Здесь подпись остаётся математически верной — подменяется
// только хэш в атрибуте, и проверка обязана это заметить.
func TestSigningCertificateCatchesMismatch(t *testing.T) {
	content := []byte("данные")
	priv, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "подмена", 3)

	der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	// Убеждаемся, что до подмены всё сходится.
	if err := sd.Verify(content); err != nil {
		t.Fatal(err)
	}

	// Портим хэш сертификата внутри подписанных атрибутов. Подпись после
	// этого перестанет сходиться, поэтому проверяем отдельно саму
	// функцию сверки: именно она отвечает за эту связь.
	attrs, err := parseAttributes(sd.Signers[0].info.SignedAttrs)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for i := range attrs {
		if !attrs[i].Type.Equal(oidSigningCertificateV2) {
			continue
		}
		found = true
		var sc signingCertificateV2
		if _, err := asn1.Unmarshal(attrs[i].Values.Bytes, &sc); err != nil {
			t.Fatal(err)
		}
		sc.Certs[0].CertHash[0] ^= 0x01
		raw, err := asn1.Marshal(sc)
		if err != nil {
			t.Fatal(err)
		}
		attrs[i].Values = asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: raw,
		}
	}
	if !found {
		t.Fatal("атрибут не найден")
	}
	if _, err := checkSigningCertificate(attrs, cert); err != ErrSigningCertificate {
		t.Fatalf("подменённый хэш сертификата: err = %v", err)
	}
}

// Чужой сертификат с тем же хэш-алгоритмом тоже обязан отвергаться.
func TestSigningCertificateRejectsOtherCertificate(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "свой", 4)
	_, other := newSignerPair(t, c, "чужой", 5)

	der, err := Sign(rand.Reader, []byte("данные"), cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := parseAttributes(sd.Signers[0].info.SignedAttrs)
	if err != nil {
		t.Fatal(err)
	}

	present, err := checkSigningCertificate(attrs, cert)
	if !present || err != nil {
		t.Fatalf("свой сертификат: present=%v err=%v", present, err)
	}
	if _, err := checkSigningCertificate(attrs, other); err != ErrSigningCertificate {
		t.Errorf("чужой сертификат: err = %v", err)
	}
}

// Серийный номер и издатель в IssuerSerial тоже участвуют в сверке.
func TestSigningCertificateChecksIssuerSerial(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "серийный", 6)

	der, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := parseAttributes(sd.Signers[0].info.SignedAttrs)
	if err != nil {
		t.Fatal(err)
	}

	var id essCertIDv2
	for _, a := range attrs {
		if a.Type.Equal(oidSigningCertificateV2) {
			var sc signingCertificateV2
			if _, err := asn1.Unmarshal(a.Values.Bytes, &sc); err != nil {
				t.Fatal(err)
			}
			id = sc.Certs[0]
		}
	}
	if len(id.IssuerSerial.FullBytes) == 0 {
		t.Fatal("IssuerSerial не выставлен")
	}
	if !checkIssuerSerial(id.IssuerSerial, cert) {
		t.Error("свой сертификат не прошёл сверку издателя и номера")
	}

	// Сертификат с другим серийным номером — тот же издатель, тот же CN.
	_, otherSerial := newSignerPair(t, c, "серийный", 7)
	if checkIssuerSerial(id.IssuerSerial, otherSerial) {
		t.Error("сертификат с другим номером прошёл сверку")
	}
}

// Хэш в атрибуте берётся тот же, которым подписывается сообщение.
func TestSigningCertificateHashMatchesDigest(t *testing.T) {
	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, cert := newSignerPair(t, tc.curve, "хэш", 8)
			der, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{Detached: true})
			if err != nil {
				t.Fatal(err)
			}
			sd, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			attrs, err := parseAttributes(sd.Signers[0].info.SignedAttrs)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range attrs {
				if !a.Type.Equal(oidSigningCertificateV2) {
					continue
				}
				var sc signingCertificateV2
				if _, err := asn1.Unmarshal(a.Values.Bytes, &sc); err != nil {
					t.Fatal(err)
				}
				var want []byte
				if priv.Curve.Size() > 32 {
					d := streebog.Sum512(cert.Raw)
					want = d[:]
				} else {
					d := streebog.Sum256(cert.Raw)
					want = d[:]
				}
				if !bytes.Equal(sc.Certs[0].CertHash, want) {
					t.Fatalf("хэш сертификата не совпал\n  в атрибуте %x\n  ожидалось  %x",
						sc.Certs[0].CertHash, want)
				}
			}
		})
	}
}

// Опущенный AlgorithmIdentifier означает SHA-256 (RFC 5035): проверяем,
// что разбор чужих подписей это учитывает.
func TestESSDigestDefaultsToSHA256(t *testing.T) {
	data := []byte("значение по умолчанию")
	got, err := essDigest(algorithmIdentifier{}, data)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("по умолчанию должен быть SHA-256, получено %x", got)
	}

	got, err = essDigest(algorithmIdentifier{Algorithm: oidSHA256}, data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatal("явный SHA-256 разошёлся с умолчанием")
	}

	if _, err := essDigest(algorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4},
	}, data); err != ErrUnsupported {
		t.Errorf("неизвестный алгоритм: err = %v", err)
	}
}

// Отсутствие атрибута — не ошибка: он необязателен на уровне CMS.
func TestCheckSigningCertificateAbsent(t *testing.T) {
	_, cert := newSignerPair(t, gost3410.TC26ParamSet256A(), "пусто", 9)
	present, err := checkSigningCertificate(nil, cert)
	if present || err != nil {
		t.Fatalf("present=%v err=%v", present, err)
	}
}
