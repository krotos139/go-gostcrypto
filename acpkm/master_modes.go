// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package acpkm

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

// Режимы работы с перевыработкой ключа по мастер-ключу: простой замены с
// зацеплением, гаммирования с обратной связью по шифртексту и выработки
// имитовставки (RFC 8645, пп. 6.3.4-6.3.6).
//
// Во всех трёх ключ секции берётся из общего потока ключевого материала,
// как описано в п. 6.3.1: блок с номером j обрабатывается ключом секции
// с номером ceil(j*n/N).

var (
	// ErrIVSize возвращается при недопустимой длине синхропосылки.
	ErrIVSize = errors.New("acpkm: синхропосылка должна занимать блок")
	// ErrTagSize возвращается при недопустимой длине имитовставки.
	ErrTagSize = errors.New("acpkm: недопустимая длина имитовставки")
	// ErrOMACBlockSize возвращается, если размер блока шифра не подходит
	// режиму выработки имитовставки.
	ErrOMACBlockSize = errors.New("acpkm: размер блока не поддерживается режимом имитовставки")
)

// --- CBC-ACPKM-Master (п. 6.3.4) ---

type cbcMaster struct {
	keys    *sectionSource
	bs      int
	prev    []byte // C_{j-1}, для первого блока - синхропосылка
	tmp     []byte
	decrypt bool
}

// NewCBCMasterEncrypter создаёт зашифрование в режиме простой замены с
// зацеплением и перевыработкой ключа по мастер-ключу.
//
// Синхропосылка занимает ровно блок. Данные обрабатываются целыми
// блоками: дополнение стандартом не определено, оно на стороне
// вызывающего кода (см. gost3413.Pad2).
func NewCBCMasterEncrypter(newCipher CipherFunc, key, iv []byte, sectionSize, masterSectionSize int) (cipher.BlockMode, error) {
	return newCBCMaster(newCipher, key, iv, sectionSize, masterSectionSize, false)
}

// NewCBCMasterDecrypter создаёт расшифрование в том же режиме.
func NewCBCMasterDecrypter(newCipher CipherFunc, key, iv []byte, sectionSize, masterSectionSize int) (cipher.BlockMode, error) {
	return newCBCMaster(newCipher, key, iv, sectionSize, masterSectionSize, true)
}

func newCBCMaster(newCipher CipherFunc, key, iv []byte, sectionSize, masterSectionSize int, decrypt bool) (cipher.BlockMode, error) {
	keys, bs, err := newSectionSource(newCipher, key, sectionSize, masterSectionSize, 0)
	if err != nil {
		return nil, err
	}
	if len(iv) != bs {
		return nil, ErrIVSize
	}
	x := &cbcMaster{
		keys:    keys,
		bs:      bs,
		prev:    make([]byte, bs),
		tmp:     make([]byte, bs),
		decrypt: decrypt,
	}
	copy(x.prev, iv) // C_0 = IV
	return x, nil
}

func (x *cbcMaster) BlockSize() int { return x.bs }

func (x *cbcMaster) CryptBlocks(dst, src []byte) {
	if len(src)%x.bs != 0 {
		panic("acpkm: длина данных не кратна размеру блока")
	}
	if len(dst) < len(src) {
		panic("acpkm: выходной буфер короче входного")
	}
	for len(src) > 0 {
		b := x.keys.next()
		if x.decrypt {
			// P_j = D(C_j) (xor) C_{j-1}; исходный блок нужно сохранить
			// до записи в dst, потому что они могут совпадать.
			copy(x.tmp, src[:x.bs])
			b.Decrypt(dst[:x.bs], src[:x.bs])
			subtle.XORBytes(dst[:x.bs], dst[:x.bs], x.prev)
			x.prev, x.tmp = x.tmp, x.prev
		} else {
			// C_j = E(P_j (xor) C_{j-1})
			subtle.XORBytes(x.tmp, src[:x.bs], x.prev)
			b.Encrypt(dst[:x.bs], x.tmp)
			copy(x.prev, dst[:x.bs])
		}
		src, dst = src[x.bs:], dst[x.bs:]
	}
}

// --- CFB-ACPKM-Master (п. 6.3.5) ---

type cfbMaster struct {
	keys    *sectionSource
	bs      int
	state   []byte // C_{j-1}
	gamma   []byte
	feed    []byte
	unused  int
	decrypt bool
}

// NewCFBMasterEncrypter создаёт зашифрование в режиме гаммирования с
// обратной связью по шифртексту и перевыработкой ключа по мастер-ключу.
//
// Длина сообщения произвольна: последний блок может быть неполным.
func NewCFBMasterEncrypter(newCipher CipherFunc, key, iv []byte, sectionSize, masterSectionSize int) (cipher.Stream, error) {
	return newCFBMaster(newCipher, key, iv, sectionSize, masterSectionSize, false)
}

// NewCFBMasterDecrypter создаёт расшифрование в том же режиме.
func NewCFBMasterDecrypter(newCipher CipherFunc, key, iv []byte, sectionSize, masterSectionSize int) (cipher.Stream, error) {
	return newCFBMaster(newCipher, key, iv, sectionSize, masterSectionSize, true)
}

func newCFBMaster(newCipher CipherFunc, key, iv []byte, sectionSize, masterSectionSize int, decrypt bool) (cipher.Stream, error) {
	keys, bs, err := newSectionSource(newCipher, key, sectionSize, masterSectionSize, 0)
	if err != nil {
		return nil, err
	}
	if len(iv) != bs {
		return nil, ErrIVSize
	}
	x := &cfbMaster{
		keys:    keys,
		bs:      bs,
		state:   make([]byte, bs),
		gamma:   make([]byte, bs),
		feed:    make([]byte, bs),
		decrypt: decrypt,
	}
	copy(x.state, iv) // C_0 = IV
	return x, nil
}

func (x *cfbMaster) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("acpkm: выходной буфер короче входного")
	}
	for len(src) > 0 {
		if x.unused == 0 {
			x.keys.next().Encrypt(x.gamma, x.state)
			x.unused = x.bs
		}
		off := x.bs - x.unused
		n := x.unused
		if n > len(src) {
			n = len(src)
		}
		for i := 0; i < n; i++ {
			// В обратную связь всегда уходит шифртекст.
			if x.decrypt {
				x.feed[off+i] = src[i]
			} else {
				x.feed[off+i] = src[i] ^ x.gamma[off+i]
			}
			dst[i] = src[i] ^ x.gamma[off+i]
		}
		x.unused -= n
		if x.unused == 0 {
			copy(x.state, x.feed)
		}
		src, dst = src[n:], dst[n:]
	}
}

// --- OMAC-ACPKM-Master (п. 6.3.6) ---

// omacConst возвращает константу R_n для сдвига добавочного ключа.
//
// Стандарт задаёт её для n = 64, 128 и 256. Отечественных шифров с
// 256-битным блоком нет, поэтому поддержаны первые два; кстати, в тексте
// RFC 8645 значение для n = 256 напечатано как 0^145 | 10000100101, хотя
// нулей должно быть 245.
func omacConst(blockSize int) (byte, bool) {
	switch blockSize {
	case 8:
		return 0x1B, true
	case 16:
		return 0x87, true
	}
	return 0, false
}

type omacMaster struct {
	keys *sectionSource
	bs   int
	size int
	c    []byte // C_{j-1}
	buf  []byte
	nx   int
	rn   byte
	// Параметры сохраняются, чтобы Reset мог начать поток ключевого
	// материала заново.
	newCipher         CipherFunc
	key               []byte
	sectionSize       int
	masterSectionSize int
}

// NewOMACMaster создаёт вычислитель имитовставки в режиме
// OMAC-ACPKM-Master (RFC 8645, п. 6.3.6).
//
// На каждую секцию из потока берётся k+n бит: ключ шифра и добавочный
// ключ K^j_1. Имитовставка длины tagSize байт вычисляется на ключе
// последней секции.
func NewOMACMaster(newCipher CipherFunc, key []byte, sectionSize, masterSectionSize, tagSize int) (hash.Hash, error) {
	probe, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := probe.BlockSize()
	rn, ok := omacConst(bs)
	if !ok {
		return nil, ErrOMACBlockSize
	}
	if tagSize <= 0 || tagSize > bs {
		return nil, ErrTagSize
	}
	keys, _, err := newSectionSource(newCipher, key, sectionSize, masterSectionSize, bs)
	if err != nil {
		return nil, err
	}
	return &omacMaster{
		keys:              keys,
		bs:                bs,
		size:              tagSize,
		c:                 make([]byte, bs),
		buf:               make([]byte, bs),
		rn:                rn,
		newCipher:         newCipher,
		key:               append([]byte(nil), key...),
		sectionSize:       sectionSize,
		masterSectionSize: masterSectionSize,
	}, nil
}

func (m *omacMaster) Size() int      { return m.size }
func (m *omacMaster) BlockSize() int { return m.bs }

// Reset начинает выработку заново: поток ключевого материала
// открывается с начала, поэтому вычислитель можно использовать повторно.
func (m *omacMaster) Reset() {
	keys, _, err := newSectionSource(m.newCipher, m.key, m.sectionSize, m.masterSectionSize, m.bs)
	if err != nil {
		// Те же параметры уже прошли проверку в конструкторе.
		panic("acpkm: повторное открытие потока не удалось: " + err.Error())
	}
	m.keys = keys
	for i := range m.c {
		m.c[i] = 0
	}
	m.nx = 0
}

// block обрабатывает полный блок, который заведомо не последний.
func (m *omacMaster) block(p []byte) {
	b := m.keys.next()
	subtle.XORBytes(m.c, m.c, p)
	b.Encrypt(m.c, m.c)
}

func (m *omacMaster) Write(p []byte) (int, error) {
	total := len(p)
	// Последний блок обрабатывается иначе, поэтому один блок всегда
	// придерживается в буфере до конца сообщения.
	for len(p) > 0 {
		if m.nx == m.bs {
			m.block(m.buf)
			m.nx = 0
		}
		n := copy(m.buf[m.nx:], p)
		m.nx += n
		p = p[n:]
	}
	return total, nil
}

// shiftLeft1 записывает в dst сдвиг src на разряд влево и возвращает
// вытесненный старший бит.
func shiftLeft1(dst, src []byte) byte {
	var carry byte
	for i := len(src) - 1; i >= 0; i-- {
		v := src[i]
		dst[i] = v<<1 | carry
		carry = v >> 7
	}
	return carry
}

func (m *omacMaster) Sum(in []byte) []byte {
	// Sum не должна менять состояние: работаем на копиях.
	c := make([]byte, m.bs)
	copy(c, m.c)

	// Имитовставка вычисляется на ключе секции, которой принадлежит
	// последний блок. Берётся он через peek: Sum не должна менять
	// состояние, иначе повторный вызов дал бы другой результат.
	b := m.keys.peek()
	extra := m.keys.extra

	last := make([]byte, m.bs)
	sk := make([]byte, m.bs)
	if m.nx == m.bs {
		// Полный последний блок: SK = K1 без сдвига.
		copy(last, m.buf)
		copy(sk, extra)
	} else {
		// Неполный: дополняется единичным битом и нулями, ключ сдвигается.
		copy(last, m.buf[:m.nx])
		last[m.nx] = 0x80
		if shiftLeft1(sk, extra) == 1 {
			sk[len(sk)-1] ^= m.rn
		}
	}

	subtle.XORBytes(last, last, c)
	subtle.XORBytes(last, last, sk)
	b.Encrypt(last, last)
	return append(in, last[:m.size]...)
}

// OMACMaster вычисляет имитовставку за один вызов.
func OMACMaster(newCipher CipherFunc, key, data []byte, sectionSize, masterSectionSize, tagSize int) ([]byte, error) {
	m, err := NewOMACMaster(newCipher, key, sectionSize, masterSectionSize, tagSize)
	if err != nil {
		return nil, err
	}
	m.Write(data)
	return m.Sum(nil), nil
}
