// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа считает хэш файла по ГОСТ Р 34.11-2012 («Стрибог»).
//
//	go run ./examples/hash-file документ.pdf
//
// Обратите внимание на порядок байт: стандарт печатает хэш развёрнутым
// относительно того, как он вычисляется. Программа выводит оба вида.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/krotos139/go-gostcrypto/gost3411/streebog"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "использование: hash-file <файл>")
		os.Exit(2)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	// Обе длины считаются за один проход по файлу.
	h256 := streebog.New256()
	h512 := streebog.New512()
	n, err := io.Copy(io.MultiWriter(h256, h512), f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Файл: %s, %d байт\n\n", os.Args[1], n)
	report("Стрибог-256", h256.Sum(nil))
	report("Стрибог-512", h512.Sum(nil))
}

func report(name string, sum []byte) {
	fmt.Printf("%s\n", name)
	fmt.Printf("  как вычисляется: %s\n", hex.EncodeToString(sum))
	fmt.Printf("  как в стандарте: %s\n\n", hex.EncodeToString(reversed(sum)))
}

// reversed возвращает развёрнутую копию: в таком виде хэш печатают
// контрольные примеры ГОСТ Р 34.11-2012.
func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
