// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Программа показывает работу с устаревшими алгоритмами: ГОСТ 28147-89
// и ГОСТ Р 34.11-94.
//
//	go run ./examples/legacy
//
// Эти алгоритмы нужны только для разбора ранее выпущенных документов.
// Для нового кода берите «Магму», «Кузнечик» и «Стрибог».
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/krotos139/go-gostcrypto/gost3412/magma"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
	"github.com/krotos139/go-gostcrypto/legacy/gost341194"
)

func main() {
	data := []byte("Данные для устаревших алгоритмов")

	fmt.Println("=== ГОСТ Р 34.11-94 ===")
	fmt.Println("Наборы подстановок у этой хэш-функции разные, и хэш от")
	fmt.Println("одних и тех же данных на них не совпадает.")
	cp := gost341194.Sum256(data)
	fmt.Printf("  CryptoPro: %s\n", hex.EncodeToString(cp[:]))

	test := gost341194.NewTest()
	test.Write(data)
	fmt.Printf("  Test     : %s\n\n", hex.EncodeToString(test.Sum(nil)))

	fmt.Println("=== ГОСТ 28147-89 ===")
	fmt.Println("Подстановки здесь тоже параметр, а не часть алгоритма.")
	key := make([]byte, gost28147.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Собственные режимы 28147-89 отличаются от режимов ГОСТ Р 34.13-2015
	// и не взаимозаменяемы с ними.
	b, err := gost28147.NewCipher(key, gost28147.ParamZ())
	if err != nil {
		panic(err)
	}
	st, err := gost28147.NewGamma(b, iv)
	if err != nil {
		panic(err)
	}
	enc := make([]byte, len(data))
	st.XORKeyStream(enc, data)
	fmt.Printf("  гаммирование: %s\n", hex.EncodeToString(enc))

	// Расшифрование в этом режиме — то же самое преобразование.
	st, err = gost28147.NewGamma(b, iv)
	if err != nil {
		panic(err)
	}
	back := make([]byte, len(enc))
	st.XORKeyStream(back, enc)
	fmt.Printf("  обратно     : %q\n", back)
	if !bytes.Equal(back, data) {
		panic("round-trip не сошёлся")
	}

	// Имитовставка использует только первые шестнадцать раундов.
	mac, err := gost28147.MAC(key, gost28147.ParamZ(), nil, data, 4)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  имитовставка: %s\n\n", hex.EncodeToString(mac))

	fmt.Println("=== 28147-89 и «Магма» — не одно и то же ===")
	fmt.Println("Алгоритм тот же, но ключ и данные разбираются в обратном")
	fmt.Println("порядке байт. На одном ключе результаты разные, и подменить")
	fmt.Println("один другим нельзя.")

	blk := make([]byte, gost28147.BlockSize)
	out28147 := make([]byte, gost28147.BlockSize)
	b.Encrypt(out28147, blk)

	mg, err := magma.NewCipher(key)
	if err != nil {
		panic(err)
	}
	outMagma := make([]byte, magma.BlockSize)
	mg.Encrypt(outMagma, blk)

	fmt.Printf("  28147-89 (набор Z): %s\n", hex.EncodeToString(out28147))
	fmt.Printf("  Магма             : %s\n", hex.EncodeToString(outMagma))
	if bytes.Equal(out28147, outMagma) {
		panic("результаты совпали, чего быть не должно")
	}
	fmt.Println("  результаты различаются, как и ожидалось")
}
