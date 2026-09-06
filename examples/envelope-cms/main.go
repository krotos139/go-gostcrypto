// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа шифрует документ получателю по его сертификату и
// расшифровывает обратно.
//
//	go run ./examples/envelope-cms документ.pdf
//
// Общего секрета сторонам не нужно: ключ согласуется алгоритмом ВКО из
// одноразовой пары отправителя и открытого ключа получателя. Так
// устроены зашифрованные сообщения CMS отечественного профиля.
//
// Пример сам создаёт получателя, чтобы показать обе стороны. В жизни
// сертификат получателя берут из справочника, а закрытый ключ есть
// только у него.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/krotos139/go-gostcrypto/cms"
	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "использование: envelope-cms <документ>")
		os.Exit(2)
	}
	doc, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}

	// Получатель: ключ и сертификат. Отправителю нужен только сертификат.
	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		fatal(err)
	}
	cert, err := selfSigned(priv, "Получатель")
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Получатель: %s\n", gostasn1.FormatName(cert.Subject))

	// Зашифрование. Ключ содержимого случайный, для каждого получателя
	// он заворачивается отдельно.
	env, err := cms.Encrypt(rand.Reader, doc, []*x509.Certificate{cert}, nil)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Зашифровано: %d байт -> %d байт\n", len(doc), len(env))

	// Разбор и расшифрование.
	ed, err := cms.ParseEnvelopedData(env)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Адресатов в сообщении: %d\n", len(ed.Recipients))

	plain, err := ed.Decrypt(priv, cert)
	if err != nil {
		fatal(err)
	}
	if !bytes.Equal(plain, doc) {
		fatal(fmt.Errorf("расшифрованное не совпало с исходным"))
	}
	fmt.Println("Расшифровано: совпадает с исходным документом")

	// Контрольный опыт: посторонний ключ не должен подходить.
	other, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		fatal(err)
	}
	otherCert, err := selfSigned(other, "Посторонний")
	if err != nil {
		fatal(err)
	}
	if _, err := ed.Decrypt(other, otherCert); err == nil {
		fatal(fmt.Errorf("посторонний ключ расшифровал сообщение"))
	} else {
		fmt.Printf("Контрольный опыт: посторонний ключ отклонён (%v)\n", err)
	}
}

// selfSigned выпускает самоподписанный сертификат: crypto/x509 не умеет
// выпускать сертификаты с отечественными алгоритмами.
func selfSigned(priv *gost3410.PrivateKey, cn string) (*x509.Certificate, error) {
	spki, err := gostasn1.MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	name, err := asn1.Marshal(pkix.Name{CommonName: cn, Country: []string{"RU"}}.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	alg, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm: gostasn1.SignatureAlgorithmOID(priv.Curve),
	})
	if err != nil {
		return nil, err
	}
	serial, err := asn1.Marshal(big.NewInt(time.Now().UnixNano()))
	if err != nil {
		return nil, err
	}
	validity, err := asn1.Marshal(struct{ NotBefore, NotAfter time.Time }{
		NotBefore: time.Now().Add(-time.Hour).UTC(),
		NotAfter:  time.Now().AddDate(1, 0, 0).UTC(),
	})
	if err != nil {
		return nil, err
	}
	version, err := asn1.Marshal(2)
	if err != nil {
		return nil, err
	}

	tbs := der(0x30, concat(der(0xA0, version), serial, alg, name, validity, name, spki))
	sig, err := gost3410.Sign(rand.Reader, priv, gostasn1.DigestForCurve(priv.Curve, tbs))
	if err != nil {
		return nil, err
	}
	sigPKIX, err := gostasn1.SignatureToPKIX(sig)
	if err != nil {
		return nil, err
	}
	sigDER, err := asn1.Marshal(asn1.BitString{Bytes: sigPKIX, BitLength: len(sigPKIX) * 8})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der(0x30, concat(tbs, alg, sigDER)))
}

func der(tag byte, body []byte) []byte {
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
