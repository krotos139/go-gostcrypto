// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import "errors"

// ErrPadding возвращается Unpad2, если дополнение повреждено.
var ErrPadding = errors.New("gost3413: некорректное дополнение")

// Pad1 дополняет сообщение нулями до кратности blockSize
// (ГОСТ Р 34.13-2015, 4.1.1).
//
// Процедура неоднозначна: сообщения P и P||0 после дополнения могут
// совпасть, поэтому для восстановления исходного сообщения нужно
// дополнительно знать его длину. Обратной функции у Pad1 нет.
func Pad1(src []byte, blockSize int) []byte {
	if blockSize <= 0 {
		panic("gost3413: неположительный размер блока")
	}
	r := len(src) % blockSize
	if r == 0 {
		return dup(src)
	}
	out := make([]byte, len(src)+blockSize-r)
	copy(out, src)
	return out
}

// Pad2 дополняет сообщение единичным битом и нулями до кратности blockSize
// (ГОСТ Р 34.13-2015, 4.1.2).
//
// Процедура однозначна, но всегда удлиняет сообщение: если длина уже кратна
// blockSize, добавляется целый блок.
func Pad2(src []byte, blockSize int) []byte {
	if blockSize <= 0 {
		panic("gost3413: неположительный размер блока")
	}
	out := make([]byte, len(src)+blockSize-len(src)%blockSize)
	copy(out, src)
	out[len(src)] = 0x80
	return out
}

// Pad3 дополняет сообщение только тогда, когда последний блок неполон
// (ГОСТ Р 34.13-2015, 4.1.3): при неполном последнем блоке применяется
// процедура 2, иначе сообщение не меняется.
//
// Процедура обязательна для режима выработки имитовставки и не
// рекомендуется для остальных режимов. Обратной функции у неё нет: по
// дополненному сообщению нельзя отличить полный последний блок от
// дополненного.
func Pad3(src []byte, blockSize int) []byte {
	if blockSize <= 0 {
		panic("gost3413: неположительный размер блока")
	}
	if len(src) > 0 && len(src)%blockSize == 0 {
		return dup(src)
	}
	return Pad2(src, blockSize)
}

// Unpad2 снимает дополнение, добавленное Pad2.
//
// Возвращает ErrPadding, если после последнего ненулевого байта стоит не
// 0x80 или если сообщение состоит из одних нулей.
func Unpad2(src []byte) ([]byte, error) {
	i := len(src) - 1
	for i >= 0 && src[i] == 0x00 {
		i--
	}
	if i < 0 || src[i] != 0x80 {
		return nil, ErrPadding
	}
	return src[:i], nil
}
