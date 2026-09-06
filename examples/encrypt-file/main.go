// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа шифрует и расшифровывает файл «Кузнечиком» в режиме MGM.
//
//	go run ./examples/encrypt-file -e документ.pdf документ.enc
//	go run ./examples/encrypt-file -d документ.enc документ.pdf
//
// Ключ выводится из пароля алгоритмом PBKDF2 по Р 50.1.111-2016.
//
// Режим MGM выбран не случайно: он не только шифрует, но и заверяет —
// изменение хотя бы одного байта шифртекста обнаруживается при
// расшифровании. Простое гаммирование такой защиты не даёт: подменить
// содержимое можно, не зная ключа.
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/kdf"
	"github.com/krotos139/go-gostcrypto/mgm"
)

const (
	saltSize   = 16
	nonceSize  = 16
	tagSize    = 16
	iterations = 100000
)

func main() {
	if len(os.Args) != 4 || (os.Args[1] != "-e" && os.Args[1] != "-d") {
		fmt.Fprintln(os.Stderr, "использование: encrypt-file -e|-d <вход> <выход>")
		os.Exit(2)
	}
	in, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatal(err)
	}

	// В настоящем приложении пароль спрашивают у пользователя, не
	// показывая ввод. Здесь он берётся из переменной окружения, чтобы
	// пример оставался неинтерактивным.
	password := []byte(os.Getenv("GOST_PASSWORD"))
	if len(password) == 0 {
		fatal(fmt.Errorf("задайте пароль в переменной окружения GOST_PASSWORD"))
	}

	var out []byte
	if os.Args[1] == "-e" {
		out, err = encrypt(in, password)
	} else {
		out, err = decrypt(in, password)
	}
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(os.Args[3], out, 0o600); err != nil {
		fatal(err)
	}
	fmt.Printf("%d байт -> %s (%d байт)\n", len(in), os.Args[3], len(out))
}

// Формат: соль ‖ синхропосылка ‖ шифртекст с имитовставкой.
func encrypt(plain, password []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Старший бит первого байта синхропосылки обязан быть нулевым.
	nonce[0] &= 0x7F

	aead, err := newAEAD(password, salt)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte(nil), salt...), nonce...)
	return aead.Seal(out, nonce, plain, nil), nil
}

func decrypt(enc, password []byte) ([]byte, error) {
	if len(enc) < saltSize+nonceSize+tagSize {
		return nil, fmt.Errorf("файл слишком короткий")
	}
	salt := enc[:saltSize]
	nonce := enc[saltSize : saltSize+nonceSize]
	body := enc[saltSize+nonceSize:]

	aead, err := newAEAD(password, salt)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		// Одна ошибка на два случая: неверный пароль и изменённый файл
		// снаружи неразличимы, и это правильно.
		return nil, fmt.Errorf("не расшифровать: неверный пароль либо файл изменён")
	}
	return plain, nil
}

func newAEAD(password, salt []byte) (interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, error) {
	key := kdf.PBKDF2(password, salt, iterations, kuznyechik.KeySize)
	b, err := kuznyechik.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mgm.NewMGM(b, tagSize)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
