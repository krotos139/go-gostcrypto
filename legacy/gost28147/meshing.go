// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost28147

import (
	"crypto/cipher"
)

// Ключевое размешивание CryptoPro (RFC 4357, п. 2.3.2).
//
// Каждые 1024 байта обработанных данных ключ и синхропосылка заменяются
// новыми:
//
//	K[i+1]   = decryptECB(K[i], C)
//	IV0[i+1] = encryptECB(K[i+1], IVn[i])
//
// где IVn[i] — состояние синхропосылки к концу очередной порции, а C —
// постоянная из стандарта. Смысл тот же, что у ACPKM: ограничить объём
// данных, обработанных на одном ключе. Все наборы параметров из RFC 4357
// требуют этого размешивания, кроме id-Gost28147-89-TestParamSet.

// MeshingPeriod — сколько байт обрабатывается на одном ключе.
const MeshingPeriod = 1024

// meshingC — постоянная C из RFC 4357, п. 2.3.2.
var meshingC = [KeySize]byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

// mesh вырабатывает следующие ключ и синхропосылку.
func mesh(key []byte, sbox *SBox, iv []byte) (nextKey, nextIV []byte, err error) {
	b, err := NewCipher(key, sbox)
	if err != nil {
		return nil, nil, err
	}
	// K[i+1] = decryptECB(K[i], C): постоянная расшифровывается на
	// текущем ключе.
	nextKey = make([]byte, KeySize)
	for i := 0; i < KeySize; i += BlockSize {
		b.Decrypt(nextKey[i:i+BlockSize], meshingC[i:i+BlockSize])
	}

	// IV0[i+1] = encryptECB(K[i+1], IVn[i]).
	nb, err := NewCipher(nextKey, sbox)
	if err != nil {
		return nil, nil, err
	}
	nextIV = make([]byte, BlockSize)
	nb.Encrypt(nextIV, iv)
	return nextKey, nextIV, nil
}

// meshedCFB — режим гаммирования с обратной связью и ключевым
// размешиванием.
type meshedCFB struct {
	sbox    *SBox
	key     []byte
	inner   cipher.Stream
	state   []byte // текущее состояние обратной связи
	done    int    // байт обработано на текущем ключе
	decrypt bool
}

// NewCFBEncrypterMeshed создаёт зашифрование в режиме гаммирования с
// обратной связью и ключевым размешиванием CryptoPro.
//
// Именно так шифруется содержимое зашифрованных сообщений CMS
// отечественного профиля (RFC 4490). Без размешивания сообщения длиннее
// 1024 байт расшифруются неверно.
func NewCFBEncrypterMeshed(key []byte, sbox *SBox, iv []byte) (cipher.Stream, error) {
	return newMeshedCFB(key, sbox, iv, false)
}

// NewCFBDecrypterMeshed создаёт расшифрование в том же режиме.
func NewCFBDecrypterMeshed(key []byte, sbox *SBox, iv []byte) (cipher.Stream, error) {
	return newMeshedCFB(key, sbox, iv, true)
}

func newMeshedCFB(key []byte, sbox *SBox, iv []byte, decrypt bool) (cipher.Stream, error) {
	if len(iv) != BlockSize {
		return nil, ErrIVSize
	}
	m := &meshedCFB{
		sbox:    sbox,
		key:     append([]byte(nil), key...),
		state:   append([]byte(nil), iv...),
		decrypt: decrypt,
	}
	if err := m.restart(); err != nil {
		return nil, err
	}
	return m, nil
}

// restart создаёт поток на текущих ключе и синхропосылке.
func (m *meshedCFB) restart() error {
	b, err := NewCipher(m.key, m.sbox)
	if err != nil {
		return err
	}
	var st cipher.Stream
	if m.decrypt {
		st, err = NewCFBDecrypter(b, m.state)
	} else {
		st, err = NewCFBEncrypter(b, m.state)
	}
	if err != nil {
		return err
	}
	m.inner = st
	m.done = 0
	return nil
}

// feedback возвращает текущее состояние обратной связи внутреннего
// потока: оно и становится IVn[i] при размешивании.
func (m *meshedCFB) feedback() []byte {
	if s, ok := m.inner.(*cfbStream); ok {
		return s.state[:]
	}
	panic("gost28147: неожиданный тип потока")
}

func (m *meshedCFB) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost28147: короткий приёмник")
	}
	for len(src) > 0 {
		if m.done == MeshingPeriod {
			// Размешивание происходит ровно на границе порции.
			key, iv, err := mesh(m.key, m.sbox, m.feedback())
			if err != nil {
				panic("gost28147: размешивание не удалось: " + err.Error())
			}
			m.key, m.state = key, iv
			if err := m.restart(); err != nil {
				panic("gost28147: размешивание не удалось: " + err.Error())
			}
		}
		n := MeshingPeriod - m.done
		if n > len(src) {
			n = len(src)
		}
		m.inner.XORKeyStream(dst[:n], src[:n])
		m.done += n
		dst, src = dst[n:], src[n:]
	}
}
