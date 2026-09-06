// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа показывает полный путь подписи документа: выработка ключа,
// выпуск сертификата, формирование открепленной подписи CMS и её
// проверка.
//
//	go run ./examples/sign-cms документ.pdf
//
// Получаются файлы документ.pdf.p7s и документ.pdf.cer. Первый — то же
// самое, что лежит рядом с документами в электронном документообороте.
//
// В жизни сертификат выпускает удостоверяющий центр, а ключ хранится в
// токене. Здесь и то и другое делается на месте, чтобы пример работал
// без внешних зависимостей.
package main

import (
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
		fmt.Fprintln(os.Stderr, "использование: sign-cms <документ>")
		os.Exit(2)
	}
	doc, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}

	// 1. Ключ подписи. Кривая 256-paramSetB — самая распространённая.
	priv, err := gost3410.GenerateKey(gost3410.TC26ParamSet256B(), rand.Reader)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Ключ выработан на кривой %s\n", priv.Curve.Name())

	// 2. Сертификат. Здесь самоподписанный; в жизни его выпускает
	//    удостоверяющий центр по запросу, который умеет строить
	//    gostasn1.CreateCertificateRequest.
	cert, err := selfSigned(priv, "Пример подписанта")
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Сертификат выпущен: %s\n", gostasn1.FormatName(cert.Subject))

	// 3. Подпись. Detached означает, что документ в неё не встраивается.
	sig, err := cms.Sign(rand.Reader, doc, cert, priv, &cms.SignOptions{
		Detached:    true,
		SigningTime: time.Now(),
	})
	if err != nil {
		fatal(err)
	}
	sigPath := os.Args[1] + ".p7s"
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		fatal(err)
	}
	certPath := os.Args[1] + ".cer"
	if err := os.WriteFile(certPath, cert.Raw, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("Подпись сохранена: %s (%d байт)\n", sigPath, len(sig))
	fmt.Printf("Сертификат сохранён: %s\n\n", certPath)

	// 4. Проверка. Так же её проверит любая другая реализация.
	sd, err := cms.Parse(sig)
	if err != nil {
		fatal(err)
	}
	if err := sd.Verify(doc); err != nil {
		fatal(fmt.Errorf("подпись не прошла проверку: %w", err))
	}
	fmt.Println("Проверка: подпись верна")

	// 5. Контрольный опыт: изменённый документ обязан отвергаться.
	//    Без такой проверки нельзя быть уверенным, что проверка вообще
	//    что-то проверяет.
	tampered := append([]byte(nil), doc...)
	if len(tampered) > 0 {
		tampered[len(tampered)/2] ^= 0x01
	} else {
		tampered = []byte{0}
	}
	if err := sd.Verify(tampered); err == nil {
		fatal(fmt.Errorf("изменённый документ прошёл проверку"))
	} else {
		fmt.Printf("Контрольный опыт: изменённый документ отклонён (%v)\n", err)
	}
}

// selfSigned выпускает самоподписанный сертификат: crypto/x509 не умеет
// выпускать сертификаты с отечественными алгоритмами, поэтому
// подписываемая часть собирается вручную.
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
	serial, err := asn1.Marshal(big.NewInt(time.Now().Unix()))
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
	version, err := asn1.Marshal(2) // v3
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
