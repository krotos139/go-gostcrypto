// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package acpkm

import (
	"crypto/cipher"
	"errors"
)

// Перевыработка ключа с мастер-ключом (RFC 8645, п. 6.3).
//
// В отличие от обычного ACPKM, ключи секций здесь не выводятся один из
// другого, а вырабатываются заранее из исходного ключа: он выступает
// мастер-ключом и сам обрабатывается режимом CTR-ACPKM. Это даёт два
// свойства, которых нет у ACPKM без мастер-ключа: ключи секций можно
// вырабатывать в произвольном порядке, а компрометация ключа секции не
// раскрывает не только предыдущие, но и последующие секции.
//
// Ключевой материал определён так (п. 6.3.1):
//
//	K[1] | ... | K[l] = ACPKM-Master(T*, K, d, l)
//	                  = CTR-ACPKM-Encrypt(T*, K, 1^{n/2}, 0^{d*l})
//
// где T* — частота смены мастер-ключа, d — длина ключевого материала на
// одну секцию, l — число секций.

// ErrMasterSectionSize возвращается при недопустимой частоте смены
// мастер-ключа.
var ErrMasterSectionSize = errors.New("acpkm: недопустимая частота смены мастер-ключа")

// masterKeyStream открывает поток ключевого материала ACPKM-Master.
//
// Синхропосылкой служит вектор из единичных бит длины n/2: она не
// пересекается со счётчиками, применяемыми к самим данным.
func masterKeyStream(newCipher CipherFunc, key []byte, masterSectionSize int) (cipher.Stream, error) {
	b, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := b.BlockSize()
	if masterSectionSize <= 0 || masterSectionSize%bs != 0 {
		return nil, ErrMasterSectionSize
	}
	icn := make([]byte, bs/2)
	for i := range icn {
		icn[i] = 0xFF
	}
	return NewCTR(newCipher, key, icn, masterSectionSize)
}

// MasterKeys вырабатывает ключевой материал K[1] | ... | K[l] из
// мастер-ключа key (RFC 8645, п. 6.3.1).
//
// Параметр masterSectionSize — частота смены мастер-ключа T* в байтах,
// d — длина материала на секцию, l — число секций. Результат имеет
// длину d*l байт.
func MasterKeys(newCipher CipherFunc, key []byte, masterSectionSize, d, l int) ([]byte, error) {
	if d <= 0 || l <= 0 {
		return nil, ErrKeySize
	}
	st, err := masterKeyStream(newCipher, key, masterSectionSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, d*l)
	st.XORKeyStream(out, out) // шифрование нулей даёт саму гамму
	return out, nil
}

// sectionSource выдаёт ключи секций по мере обработки блоков.
//
// Ключевой материал берётся из потока ACPKM-Master порциями по
// keyLen+extraLen байт: keyLen уходит в шифр, extraLen — это добавочный
// ключ K^j_1, который нужен только режиму выработки имитовставки.
type sectionSource struct {
	stream     cipher.Stream
	newCipher  CipherFunc
	keyLen     int
	extraLen   int
	perSection int // блоков в секции
	used       int // блоков обработано в текущей секции
	cur        cipher.Block
	extra      []byte
}

func newSectionSource(newCipher CipherFunc, key []byte, sectionSize, masterSectionSize, extraLen int) (*sectionSource, int, error) {
	probe, err := newCipher(key)
	if err != nil {
		return nil, 0, err
	}
	bs := probe.BlockSize()
	if sectionSize <= 0 || sectionSize%bs != 0 {
		return nil, 0, ErrSectionSize
	}
	stream, err := masterKeyStream(newCipher, key, masterSectionSize)
	if err != nil {
		return nil, 0, err
	}
	return &sectionSource{
		stream:     stream,
		newCipher:  newCipher,
		keyLen:     len(key),
		extraLen:   extraLen,
		perSection: sectionSize / bs,
	}, bs, nil
}

// peek возвращает шифр для очередного блока, не засчитывая сам блок.
//
// Повторный вызов даёт тот же ключ и не двигает поток: это нужно режиму
// имитовставки, где Sum обязана не менять состояние.
func (s *sectionSource) peek() cipher.Block {
	if s.cur == nil || s.used == s.perSection {
		buf := make([]byte, s.keyLen+s.extraLen)
		s.stream.XORKeyStream(buf, buf)
		b, err := s.newCipher(buf[:s.keyLen])
		if err != nil {
			// Длина ключа не меняется, поэтому сюда не попасть.
			panic("acpkm: выработка ключа секции не удалась: " + err.Error())
		}
		s.cur = b
		s.extra = buf[s.keyLen:]
		s.used = 0
	}
	return s.cur
}

// next возвращает шифр для очередного блока и засчитывает его.
func (s *sectionSource) next() cipher.Block {
	b := s.peek()
	s.used++
	return b
}

// ctrMaster реализует режим CTR-ACPKM-Master.
type ctrMaster struct {
	keys *sectionSource
	b    cipher.Block
	bs   int
	ctr  []byte
	cLen int
	ks   []byte
	pos  int
}

// NewCTRMaster создаёт cipher.Stream для режима CTR-ACPKM-Master
// (RFC 8645, п. 6.3.2).
//
// Параметр sectionSize задаёт размер секции N в байтах, а
// masterSectionSize — частоту смены мастер-ключа T*; оба должны быть
// положительными кратными размеру блока. Длина синхропосылки определяет
// размер счётчика так же, как в NewCTR.
//
// Значение ICN должно быть уникальным для каждого сообщения,
// зашифрованного на одном исходном ключе. Как и всякое гаммирование,
// режим совмещает зашифрование с расшифрованием.
func NewCTRMaster(newCipher CipherFunc, key, icn []byte, sectionSize, masterSectionSize int) (cipher.Stream, error) {
	keys, bs, err := newSectionSource(newCipher, key, sectionSize, masterSectionSize, 0)
	if err != nil {
		return nil, err
	}
	cLen := bs - len(icn)
	if cLen < 4 || cLen*4 > bs*3 {
		return nil, ErrICNSize
	}

	x := &ctrMaster{
		keys: keys,
		bs:   bs,
		ctr:  make([]byte, bs),
		cLen: cLen,
		ks:   make([]byte, bs),
	}
	copy(x.ctr, icn) // CTR_1 = ICN || 0^c
	x.pos = bs
	return x, nil
}

func (x *ctrMaster) next() {
	x.b = x.keys.next()
	x.b.Encrypt(x.ks, x.ctr)
	x.pos = 0

	// Inc_c: инкремент младших cLen байт счётчика.
	for i := x.bs - 1; i >= x.bs-x.cLen; i-- {
		x.ctr[i]++
		if x.ctr[i] != 0 {
			break
		}
	}
}

func (x *ctrMaster) XORKeyStream(dst, src []byte) {
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
