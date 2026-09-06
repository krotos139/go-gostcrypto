// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа разбирает файл открепленной подписи (.p7s, .sig) и, если
// передан подписанный документ, проверяет подпись.
//
// Показывает то, что обычно нужно при разборе чужой подписи: кем
// подписано, чем, когда по заявлению подписанта, есть ли метка времени
// и ссылка на сертификат, из каких сертификатов состоит вложенная
// цепочка.
//
//	go run ./examples/inspect-signature подпись.p7s документ.pdf
//	go run ./examples/inspect-signature подпись.sig
//
// Проверка подписи означает только её математическую верность. Доверие
// к сертификату, срок его действия и отзыв здесь не проверяются: это
// отдельная задача, и библиотека её намеренно не решает.
package main

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/krotos139/go-gostcrypto/cms"
	"github.com/krotos139/go-gostcrypto/gostasn1"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "использование: inspect-signature <подпись> [документ]")
		os.Exit(2)
	}

	der, err := readDER(os.Args[1])
	if err != nil {
		fatal("не прочитать подпись: %v", err)
	}
	sd, err := cms.Parse(der)
	if err != nil {
		fatal("разбор не удался: %v", err)
	}

	fmt.Printf("Подпись: %d байт, %s\n", len(der), detachedWord(sd.Detached))
	fmt.Printf("Вложено сертификатов: %d, подписантов: %d\n\n", len(sd.Certificates), len(sd.Signers))

	var content []byte
	if len(os.Args) > 2 {
		if content, err = os.ReadFile(os.Args[2]); err != nil {
			fatal("не прочитать документ: %v", err)
		}
		fmt.Printf("Документ: %s, %d байт\n\n", os.Args[2], len(content))
	} else if sd.Detached {
		fmt.Println("Документ не передан: подпись открепленная, проверить её нечем.")
		fmt.Println()
	}

	for i, s := range sd.Signers {
		describeSigner(i, s)
		if sd.Detached && content == nil {
			fmt.Println()
			continue
		}
		if err := sd.VerifySigner(s, content); err != nil {
			fmt.Printf("  итог        : ПОДПИСЬ НЕ ПРОШЛА: %v\n\n", err)
			continue
		}
		fmt.Printf("  итог        : подпись верна\n\n")
	}

	if len(sd.Certificates) > 0 {
		fmt.Println("Вложенные сертификаты:")
		for _, c := range sd.Certificates {
			fmt.Printf("  %s\n", gostasn1.FormatName(c.Subject))
			fmt.Printf("    выдан    : %s\n", gostasn1.FormatName(c.Issuer))
			fmt.Printf("    действует: %s - %s\n",
				c.NotBefore.Format("02.01.2006"), c.NotAfter.Format("02.01.2006"))
			if st := gostasn1.SignTools(c); st.Subject != "" {
				fmt.Printf("    средство : %s\n", st.Subject)
			}
		}
	}
}

func describeSigner(i int, s *cms.Signer) {
	fmt.Printf("Подписант %d\n", i)
	if s.Certificate != nil {
		fmt.Printf("  кто         : %s\n", gostasn1.FormatName(s.Certificate.Subject))
		fmt.Printf("  выдан       : %s\n", gostasn1.FormatName(s.Certificate.Issuer))
		if attrs := gostasn1.Attributes(s.Certificate.Subject); len(attrs) > 0 {
			for _, k := range []string{"INN", "SNILS", "OGRN", "OGRNIP", "INNLE"} {
				if v, ok := attrs[k]; ok {
					fmt.Printf("  %-11s : %s\n", k, v)
				}
			}
		}
	} else {
		fmt.Println("  кто         : сертификат в подпись не вложен")
	}
	fmt.Printf("  хэш         : %s\n", algName(s.DigestAlgorithm.String()))
	fmt.Printf("  подпись     : %s\n", algName(s.SignatureAlgorithm.String()))
	if s.HasSigningTime {
		fmt.Printf("  время       : %s (заявлено подписантом, не метка времени)\n",
			s.SigningTime.Format("02.01.2006 15:04:05 MST"))
	}
	fmt.Printf("  ссылка CAdES: %v\n", s.HasSigningCertificate)

	stamps, err := s.Timestamps()
	switch {
	case err != nil:
		fmt.Printf("  метка времени: не разобрана: %v\n", err)
	case len(stamps) == 0:
		fmt.Printf("  метка времени: нет\n")
	default:
		for _, ts := range stamps {
			status := "не проверена"
			if err := ts.Verify(s.SignatureValue()); err == nil {
				status = "проверена"
			} else {
				status = fmt.Sprintf("НЕ ПРОШЛА: %v", err)
			}
			fmt.Printf("  метка времени: %s (%s)\n",
				ts.GenTime.Format("02.01.2006 15:04:05 MST"), status)
		}
	}
}

// algName подставляет читаемые названия вместо голых идентификаторов.
func algName(oid string) string {
	switch oid {
	case "1.2.643.7.1.1.2.2":
		return "Стрибог-256 (" + oid + ")"
	case "1.2.643.7.1.1.2.3":
		return "Стрибог-512 (" + oid + ")"
	case "1.2.643.2.2.9":
		return "ГОСТ Р 34.11-94, устаревший (" + oid + ")"
	case "1.2.643.7.1.1.1.1":
		return "ГОСТ Р 34.10-2012, 256 бит (" + oid + ")"
	case "1.2.643.7.1.1.1.2":
		return "ГОСТ Р 34.10-2012, 512 бит (" + oid + ")"
	case "1.2.643.2.2.19":
		return "ГОСТ Р 34.10-2001, устаревший (" + oid + ")"
	case "1.2.643.7.1.1.3.2":
		return "ГОСТ Р 34.10-2012 со Стрибогом-256 (" + oid + ")"
	case "1.2.643.7.1.1.3.3":
		return "ГОСТ Р 34.10-2012 со Стрибогом-512 (" + oid + ")"
	case "1.2.643.2.2.3":
		return "ГОСТ Р 34.10-2001 с 34.11-94, устаревший (" + oid + ")"
	}
	return oid
}

func detachedWord(detached bool) string {
	if detached {
		return "открепленная"
	}
	return "со встроенным содержимым"
}

// readDER принимает DER, PEM и base64: подписи попадаются во всех трёх
// видах.
func readDER(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 && raw[0] == 0x30 {
		return raw, nil
	}
	if b, _ := pem.Decode(raw); b != nil {
		return b.Bytes, nil
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, string(raw))
	return base64.StdEncoding.DecodeString(clean)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
