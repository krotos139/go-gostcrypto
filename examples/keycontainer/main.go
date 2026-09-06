// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа читает транспортный ключевой контейнер PKCS#12 (.pfx, .p12)
// и показывает, что в нём лежит.
//
//	GOST_PASSWORD=пароль go run ./examples/keycontainer контейнер.pfx
//
// Пароль берётся из переменной окружения, чтобы не попадать в историю
// команд. В настоящем приложении его спрашивают у пользователя, не
// показывая ввод.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/pfx"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "использование: keycontainer <контейнер.pfx>")
		fmt.Fprintln(os.Stderr, "пароль задаётся переменной окружения GOST_PASSWORD")
		os.Exit(2)
	}
	der, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	password := []byte(os.Getenv("GOST_PASSWORD"))

	c, err := pfx.Parse(der, password)
	if err != nil {
		// Отдельное сообщение на самый частый случай: имитовставка не
		// сходится и при неверном пароле, и при повреждении файла.
		if err == pfx.ErrMAC {
			fatal(fmt.Errorf("имитовставка не совпала: неверный пароль либо файл повреждён"))
		}
		fatal(err)
	}

	fmt.Printf("Контейнер: %s, %d байт\n", os.Args[1], len(der))
	fmt.Printf("Целостность подтверждена: %s\n", integrity(c))
	if c.SkippedSections > 0 {
		fmt.Printf("Пропущено разделов: %d (зашифрованы не паролем)\n", c.SkippedSections)
	}
	fmt.Println()

	for i, k := range c.Keys {
		fmt.Printf("Ключ %d\n", i)
		fmt.Printf("  кривая     : %s (%d бит)\n", k.Key.Curve.Name(), k.Key.Curve.Size()*8)
		fmt.Printf("  хранился   : %s\n", shrouded(k.Encrypted))
		if len(k.LocalKeyID) > 0 {
			fmt.Printf("  метка      : %s\n", hex.EncodeToString(k.LocalKeyID))
		}
		if k.FriendlyName != "" {
			fmt.Printf("  имя        : %s\n", k.FriendlyName)
		}
		if cert := c.CertificateFor(k); cert != nil {
			fmt.Printf("  сертификат : %s\n", gostasn1.FormatName(cert.Subject))
		} else {
			fmt.Printf("  сертификат : не найден\n")
		}
		fmt.Println()
	}

	fmt.Printf("Сертификатов: %d\n", len(c.Certificates))
	for _, ce := range c.Certificates {
		fmt.Printf("  %s\n", gostasn1.FormatName(ce.Certificate.Subject))
		fmt.Printf("    выдан    : %s\n", gostasn1.FormatName(ce.Certificate.Issuer))
		fmt.Printf("    действует: %s - %s\n",
			ce.Certificate.NotBefore.Format("02.01.2006"),
			ce.Certificate.NotAfter.Format("02.01.2006"))
	}
}

func integrity(c *pfx.Container) string {
	switch {
	case c.HasMAC:
		return "имитовставкой на пароле"
	case len(c.Signers) > 0:
		return "подписью отправителя: " + gostasn1.FormatName(c.Signers[0].Subject)
	}
	return "ничем"
}

func shrouded(encrypted bool) string {
	if encrypted {
		return "зашифрованным отдельно (pkcs8ShroudedKeyBag)"
	}
	return "в открытом портфеле (keyBag)"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
