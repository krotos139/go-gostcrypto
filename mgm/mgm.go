// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package mgm реализует режим аутентифицированного шифрования MGM
// (Multilinear Galois Mode) из Р 1323565.1.026-2019, он же RFC 9058.
//
// MGM — режим AEAD для блочных шифров с длиной блока 64 или 128 бит,
// то есть для "Магмы" и "Кузнечика". Он реализует cipher.AEAD, поэтому
// подходит везде, где ожидается стандартный интерфейс Go.
//
// # Синхропосылка
//
// В терминах стандарта синхропосылка ICN имеет длину n-1 бит: старший
// разряд отведён под различение двух потоков — гаммы шифра и
// последовательности для имитовставки. Здесь синхропосылка задаётся
// целым числом байт (n/8), и её старший бит обязан быть нулевым;
// иначе Seal и Open вызывают панику, как и предписывает контракт
// cipher.AEAD для некорректной синхропосылки.
//
// Значение ICN должно быть уникальным для каждого сообщения,
// зашифрованного на одном ключе. Повторное использование раскрывает
// открытый текст и позволяет подделывать имитовставки.
package mgm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strconv"
	"unsafe"
)

// MinTagSize — наименьшая допустимая длина имитовставки в байтах
// (стандарт задаёт 32 <= S <= n).
const MinTagSize = 4

var (
	// ErrOpen возвращается Open, если имитовставка не сошлась.
	ErrOpen = errors.New("mgm: имитовставка не совпала")
	// ErrBlockSize возвращается NewMGM для шифра с неподдерживаемым блоком.
	ErrBlockSize = errors.New("mgm: поддерживаются блоки только 64 и 128 бит")
	// ErrTagSize возвращается NewMGM при недопустимой длине имитовставки.
	ErrTagSize = errors.New("mgm: недопустимая длина имитовставки")
)

type mgm struct {
	b       cipher.Block
	bs      int // длина блока в байтах
	half    int // bs/2
	tagSize int // длина имитовставки в байтах
}

var _ cipher.AEAD = (*mgm)(nil)

// NewMGM создаёт режим MGM с имитовставкой длины tagSize байт
// (от MinTagSize до размера блока).
func NewMGM(b cipher.Block, tagSize int) (cipher.AEAD, error) {
	bs := b.BlockSize()
	if bs != 8 && bs != 16 {
		return nil, ErrBlockSize
	}
	if tagSize < MinTagSize || tagSize > bs {
		return nil, ErrTagSize
	}
	return &mgm{b: b, bs: bs, half: bs / 2, tagSize: tagSize}, nil
}

func (m *mgm) NonceSize() int { return m.bs }
func (m *mgm) Overhead() int  { return m.tagSize }

// Умножение в поле GF(2^n) выполняется над машинными словами, а не над
// срезом байт: сдвиг 16-байтового среза стоил бы шестнадцати операций на
// каждый разряд.
//
// Множитель обрабатывается по четыре разряда: заранее строятся все
// шестнадцать кратных первого операнда, и на каждый полубайт второго
// приходится один сдвиг на четыре разряда и одно сложение.
//
// Окно берётся по ВТОРОМУ операнду. В обоих вызовах это открытые данные —
// блок связанных данных, блок шифртекста или пара длин, — а секретное
// значение H попадает в содержимое таблицы, но не в её индекс. Поэтому
// адрес выборки не зависит от секрета.

// red128 приводит вынесенный за разрядную сетку полубайт по модулю
// f(w) = w^128 + w^7 + w^2 + w + 1, red64 — по модулю
// f(w) = w^64 + w^4 + w^3 + w + 1.
var red128, red64 [16]uint64

func init() {
	for t := 0; t < 16; t++ {
		var v128, v64 uint64
		for b := 0; b < 4; b++ {
			if t&(1<<uint(b)) != 0 {
				v128 ^= 0x87 << uint(b)
				v64 ^= 0x1b << uint(b)
			}
		}
		red128[t], red64[t] = v128, v64
	}
}

// mul64 умножает в GF(2^64).
func mul64(x, y uint64) uint64 {
	var tbl [16]uint64
	tbl[1] = x
	for j := 2; j < 16; j += 2 {
		// tbl[j] = tbl[j/2] * w
		h := tbl[j/2] >> 63
		tbl[j] = tbl[j/2]<<1 ^ (0x1b & -h)
		tbl[j+1] = tbl[j] ^ x
	}

	var z uint64
	for i := 0; i < 16; i++ {
		top := z >> 60
		z = z<<4 ^ red64[top]
		z ^= tbl[(y>>(60-4*uint(i)))&0xf]
	}
	return z
}

// mul128 умножает в GF(2^128).
func mul128(xHi, xLo, yHi, yLo uint64) (uint64, uint64) {
	var tblHi, tblLo [16]uint64
	tblHi[1], tblLo[1] = xHi, xLo
	for j := 2; j < 16; j += 2 {
		h := tblHi[j/2] >> 63
		tblHi[j] = tblHi[j/2]<<1 | tblLo[j/2]>>63
		tblLo[j] = tblLo[j/2]<<1 ^ (0x87 & -h)
		tblHi[j+1], tblLo[j+1] = tblHi[j]^xHi, tblLo[j]^xLo
	}

	var zHi, zLo uint64
	step := func(nib uint64) {
		top := zHi >> 60
		zHi = zHi<<4 | zLo>>60
		zLo = zLo<<4 ^ red128[top]
		zHi ^= tblHi[nib]
		zLo ^= tblLo[nib]
	}
	for i := 0; i < 16; i++ {
		step((yHi >> (60 - 4*uint(i))) & 0xf)
	}
	for i := 0; i < 16; i++ {
		step((yLo >> (60 - 4*uint(i))) & 0xf)
	}
	return zHi, zLo
}

// mulInto вычисляет dst = x (x) y для текущего размера блока.
func (m *mgm) mulInto(dst, x, y []byte) {
	if m.bs == 8 {
		binary.BigEndian.PutUint64(dst,
			mul64(binary.BigEndian.Uint64(x), binary.BigEndian.Uint64(y)))
		return
	}
	hi, lo := mul128(
		binary.BigEndian.Uint64(x[0:8]), binary.BigEndian.Uint64(x[8:16]),
		binary.BigEndian.Uint64(y[0:8]), binary.BigEndian.Uint64(y[8:16]))
	binary.BigEndian.PutUint64(dst[0:8], hi)
	binary.BigEndian.PutUint64(dst[8:16], lo)
}

// incr увеличивает содержимое среза как целое в сетевом порядке байт.
func incr(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func (m *mgm) checkNonce(nonce []byte) {
	if len(nonce) != m.bs {
		panic("mgm: длина синхропосылки " + strconv.Itoa(len(nonce)) +
			" вместо " + strconv.Itoa(m.bs))
	}
	if nonce[0]&0x80 != 0 {
		panic("mgm: старший бит синхропосылки должен быть нулевым")
	}
}

// crypt накладывает гамму на src: шифрование и расшифрование совпадают.
func (m *mgm) crypt(dst, src, nonce []byte) {
	if len(src) == 0 {
		return
	}
	y := make([]byte, m.bs)
	gamma := make([]byte, m.bs)

	copy(y, nonce)    // 0^1 || ICN
	m.b.Encrypt(y, y) // Y_1

	for off := 0; off < len(src); off += m.bs {
		m.b.Encrypt(gamma, y)
		n := len(src) - off
		if n > m.bs {
			n = m.bs
		}
		subtle.XORBytes(dst[off:off+n], src[off:off+n], gamma[:n])
		incr(y[m.half:]) // incr_r
	}
}

// tag вычисляет имитовставку по связанным данным и шифртексту.
func (m *mgm) tag(dst, nonce, ad, ct []byte) {
	z := make([]byte, m.bs)
	h := make([]byte, m.bs)
	sum := make([]byte, m.bs)
	prod := make([]byte, m.bs)
	blk := make([]byte, m.bs)

	copy(z, nonce)
	z[0] |= 0x80      // 1^1 || ICN
	m.b.Encrypt(z, z) // Z_1

	// Неполный блок дополняется нулями справа (шаг 2 стандарта).
	feed := func(data []byte) {
		for off := 0; off < len(data); off += m.bs {
			n := len(data) - off
			if n > m.bs {
				n = m.bs
			}
			for i := range blk {
				blk[i] = 0
			}
			copy(blk, data[off:off+n])

			m.b.Encrypt(h, z)
			m.mulInto(prod, h, blk)
			subtle.XORBytes(sum, sum, prod)
			incr(z[:m.half]) // incr_l
		}
	}
	feed(ad)
	feed(ct)

	// Последний множитель — длины связанных данных и шифртекста в битах,
	// по n/2 разрядов каждая.
	lens := make([]byte, m.bs)
	putLen(lens[:m.half], uint64(len(ad))*8)
	putLen(lens[m.half:], uint64(len(ct))*8)

	m.b.Encrypt(h, z)
	m.mulInto(prod, h, lens)
	subtle.XORBytes(sum, sum, prod)

	m.b.Encrypt(sum, sum)
	copy(dst, sum[:m.tagSize])
}

// putLen записывает длину в сетевом порядке байт в поле шириной len(dst).
func putLen(dst []byte, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	if len(dst) >= 8 {
		copy(dst[len(dst)-8:], buf[:])
		return
	}
	copy(dst, buf[8-len(dst):])
}

func (m *mgm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	m.checkNonce(nonce)
	if len(additionalData) == 0 && len(plaintext) == 0 {
		panic("mgm: пустые и открытый текст, и связанные данные")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+m.tagSize)
	if inexactOverlap(out, plaintext) {
		panic("mgm: буферы назначения и источника перекрываются частично")
	}

	m.crypt(out[:len(plaintext)], plaintext, nonce)
	m.tag(out[len(plaintext):], nonce, additionalData, out[:len(plaintext)])
	return ret
}

func (m *mgm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	m.checkNonce(nonce)
	if len(ciphertext) < m.tagSize {
		return nil, ErrOpen
	}
	ct, want := ciphertext[:len(ciphertext)-m.tagSize], ciphertext[len(ciphertext)-m.tagSize:]
	if len(additionalData) == 0 && len(ct) == 0 {
		return nil, ErrOpen
	}

	got := make([]byte, m.tagSize)
	m.tag(got, nonce, additionalData, ct)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, ErrOpen
	}

	ret, out := sliceForAppend(dst, len(ct))
	if inexactOverlap(out, ct) {
		panic("mgm: буферы назначения и источника перекрываются частично")
	}
	m.crypt(out, ct, nonce)
	return ret, nil
}

// sliceForAppend повторяет вспомогательную функцию из crypto/cipher.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// inexactOverlap сообщает, перекрываются ли срезы иначе, чем начинаясь с
// одного адреса: шифрование "на месте" допустимо, частичное наложение
// молча испортило бы данные.
//
// unsafe используется только для сравнения адресов, без разыменования и
// без преобразования типов — так же, как во внутреннем пакете
// crypto/internal/alias стандартной библиотеки, недоступном извне.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}
