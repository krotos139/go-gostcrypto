// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package acpkm реализует внутреннюю перевыработку ключа ACPKM и режим
// шифрования CTR-ACPKM из Р 1323565.1.017-2018 (RFC 8645, пп. 6.2.1
// и 6.2.2).
//
// Смысл ACPKM — ограничить объём данных, обработанных на одном ключе, не
// требуя нового согласования ключей. Сообщение делится на секции по N бит;
// первая секция шифруется исходным ключом, а перед каждой следующей ключ
// преобразуется:
//
//	K^{i+1} = ACPKM(K^i) = MSB_k(E_{K^i}(D_1) | ... | E_{K^i}(D_J))
//
// Преобразование необратимо, поэтому компрометация ключа секции не
// раскрывает предыдущие секции.
//
// Режим не зависит от конкретного шифра: он работает с любым
// cipher.Block, у которого длина блока делит размер секции.
package acpkm

import (
	"crypto/cipher"
	"errors"
)

var (
	// ErrSectionSize возвращается при недопустимом размере секции.
	ErrSectionSize = errors.New("acpkm: размер секции должен быть положительным кратным размеру блока")
	// ErrICNSize возвращается при недопустимой длине синхропосылки.
	ErrICNSize = errors.New("acpkm: недопустимая длина синхропосылки")
	// ErrKeySize возвращается, если длина ключа несовместима с шифром.
	ErrKeySize = errors.New("acpkm: недопустимая длина ключа")
)

// constD — константа D из RFC 8645, п. 6.2.1: последовательность байт от
// 0x80 до 0xff. Старший бит каждого байта равен единице — это исключает
// совпадение входов шифра при перевыработке ключа и при обработке данных.
var constD = func() [128]byte {
	var d [128]byte
	for i := range d {
		d[i] = byte(0x80 + i)
	}
	return d
}()

// CipherFunc создаёт блочный шифр по ключу. Перевыработка ключа требует
// создания нового экземпляра шифра, поэтому режиму нужен конструктор,
// а не готовый cipher.Block.
type CipherFunc func(key []byte) (cipher.Block, error)

// Derive выполняет преобразование ACPKM над ключом шифра b и возвращает
// новый ключ длины keyLen байт.
func Derive(b cipher.Block, keyLen int) ([]byte, error) {
	bs := b.BlockSize()
	if keyLen <= 0 || keyLen > len(constD) {
		return nil, ErrKeySize
	}
	j := (keyLen + bs - 1) / bs
	if j*bs > len(constD) {
		return nil, ErrKeySize
	}

	out := make([]byte, j*bs)
	for i := 0; i < j; i++ {
		b.Encrypt(out[i*bs:(i+1)*bs], constD[i*bs:(i+1)*bs])
	}
	return out[:keyLen], nil
}

// ctrACPKM реализует режим CTR-ACPKM.
type ctrACPKM struct {
	newCipher  CipherFunc
	b          cipher.Block
	key        []byte
	bs         int
	ctr        []byte
	cLen       int // длина счётчика в байтах
	ks         []byte
	pos        int
	perSection int // блоков в секции
	done       int // обработано блоков в текущей секции
}

// NewCTR создаёт cipher.Stream для режима CTR-ACPKM.
//
// Параметр sectionSize задаёт размер секции N в байтах и должен быть
// положительным кратным размеру блока. Длина синхропосылки определяет
// размер счётчика c = n - |ICN|; стандарт требует 32 <= c <= 3n/4,
// причём c кратно восьми.
//
// Значение ICN должно быть уникальным для каждого сообщения,
// зашифрованного на одном исходном ключе.
func NewCTR(newCipher CipherFunc, key, icn []byte, sectionSize int) (cipher.Stream, error) {
	b, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := b.BlockSize()

	if sectionSize <= 0 || sectionSize%bs != 0 {
		return nil, ErrSectionSize
	}
	cLen := bs - len(icn)
	if cLen < 4 || cLen*4 > bs*3 {
		return nil, ErrICNSize
	}
	if _, err := Derive(b, len(key)); err != nil {
		return nil, err
	}

	x := &ctrACPKM{
		newCipher:  newCipher,
		b:          b,
		key:        append([]byte(nil), key...),
		bs:         bs,
		ctr:        make([]byte, bs),
		cLen:       cLen,
		ks:         make([]byte, bs),
		perSection: sectionSize / bs,
	}
	copy(x.ctr, icn) // CTR_1 = ICN || 0^c
	x.pos = bs       // первая же операция выработает гамму
	return x, nil
}

// rekey заменяет ключ секции на следующий.
func (x *ctrACPKM) rekey() error {
	next, err := Derive(x.b, len(x.key))
	if err != nil {
		return err
	}
	b, err := x.newCipher(next)
	if err != nil {
		return err
	}
	x.key, x.b = next, b
	return nil
}

func (x *ctrACPKM) next() {
	if x.done == x.perSection {
		if err := x.rekey(); err != nil {
			// Ключ и шифр уже проверены в NewCTR, поэтому сюда не попасть.
			panic("acpkm: перевыработка ключа не удалась: " + err.Error())
		}
		x.done = 0
	}
	x.b.Encrypt(x.ks, x.ctr)
	x.pos = 0
	x.done++

	// Inc_c: инкремент младших cLen байт счётчика.
	for i := x.bs - 1; i >= x.bs-x.cLen; i-- {
		x.ctr[i]++
		if x.ctr[i] != 0 {
			break
		}
	}
}

func (x *ctrACPKM) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("acpkm: выходной буфер короче входного")
	}
	for len(src) > 0 {
		if x.pos == x.bs {
			x.next()
		}
		n := x.bs - x.pos
		if n > len(src) {
			n = len(src)
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ x.ks[x.pos+i]
		}
		x.pos += n
		src, dst = src[n:], dst[n:]
	}
}
