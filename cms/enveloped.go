// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/keywrap"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
	"github.com/krotos139/go-gostcrypto/vko"
)

// Зашифрованные сообщения CMS отечественного профиля (RFC 4490).
//
// Устройство такое: содержимое шифруется случайным ключом CEK, а сам CEK
// заворачивается отдельно для каждого получателя. Ключ заворачивания KEK
// получается алгоритмом ВКО из одноразового ключа отправителя и открытого
// ключа получателя, поэтому получатель восстанавливает тот же KEK своим
// секретным ключом.
//
// # Что поддерживается
//
// Профиль RFC 4490 с транспортом ключа (KeyTransRecipientInfo): содержимое
// шифруется ГОСТ 28147-89 в режиме гаммирования с обратной связью и
// ключевым размешиванием, ключ заворачивается алгоритмом CryptoPro.
// Работает как с ключами ГОСТ Р 34.10-2001, так и с 2012 — ВКО выбирается
// по кривой.
//
// Современного профиля на «Кузнечике» здесь нет: публично доступного
// нормативного описания найти не удалось.

var (
	// oidEnvelopedData — id-envelopedData (RFC 5652).
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	// oidGost28147 — id-Gost28147-89, шифрование содержимого.
	oidGost28147 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}
)

var (
	// ErrNoRecipient возвращается, если сообщение не адресовано этому
	// получателю либо ключ не подошёл.
	ErrNoRecipient = errors.New("cms: получатель не найден среди адресатов сообщения")
	// ErrRecipients возвращается, если список получателей пуст.
	ErrRecipients = errors.New("cms: не указан ни один получатель")
)

// --- структуры ASN.1 ---

type gost28147Parameters struct {
	IV                 []byte
	EncryptionParamSet asn1.ObjectIdentifier
}

type gost28147EncryptedKey struct {
	EncryptedKey []byte
	MaskKey      []byte `asn1:"optional,tag:0"`
	MACKey       []byte
}

type gostTransportParameters struct {
	EncryptionParamSet asn1.ObjectIdentifier
	EphemeralPublicKey asn1.RawValue `asn1:"optional,tag:0"`
	UKM                []byte
}

type gostKeyTransport struct {
	SessionEncryptedKey gost28147EncryptedKey
	TransportParameters gostTransportParameters `asn1:"optional,tag:0"`
}

type keyTransRecipientInfo struct {
	Version                int
	RID                    asn1.RawValue
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}

type envelopedDataASN1 struct {
	Version              int
	OriginatorInfo       asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
	UnprotectedAttrs     asn1.RawValue `asn1:"optional,tag:1"`
}

// --- разбор и расшифрование ---

// EnvelopedData — разобранное зашифрованное сообщение.
type EnvelopedData struct {
	// Recipients — сведения об адресатах.
	Recipients []*Recipient
	// ContentType — тип зашифрованного содержимого, обычно id-data.
	ContentType asn1.ObjectIdentifier

	encrypted []byte
	iv        []byte
	sbox      *gost28147.SBox
	paramSet  asn1.ObjectIdentifier
}

// Recipient — один адресат сообщения.
type Recipient struct {
	// Issuer и SerialNumber указывают на сертификат адресата.
	Issuer       asn1.RawValue
	SerialNumber *big.Int

	transport gostKeyTransport
	algorithm algorithmIdentifier
}

// ParseEnvelopedData разбирает зашифрованное сообщение CMS.
func ParseEnvelopedData(der []byte) (*EnvelopedData, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		return nil, ErrUnsupported
	}

	var raw envelopedDataASN1
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &raw); err != nil {
		return nil, ErrMalformed
	}
	if !raw.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(oidGost28147) {
		return nil, ErrUnsupported
	}

	var params gost28147Parameters
	if _, err := asn1.Unmarshal(
		raw.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, ErrMalformed
	}
	if len(params.IV) != gost28147.BlockSize {
		return nil, ErrMalformed
	}
	sbox, err := gostasn1.SBoxByOID(params.EncryptionParamSet)
	if err != nil {
		return nil, err
	}

	ed := &EnvelopedData{
		ContentType: raw.EncryptedContentInfo.ContentType,
		iv:          params.IV,
		sbox:        sbox,
		paramSet:    params.EncryptionParamSet,
	}

	// Содержимое лежит в неявном [0] как OCTET STRING.
	if len(raw.EncryptedContentInfo.EncryptedContent.Bytes) > 0 {
		ed.encrypted = raw.EncryptedContentInfo.EncryptedContent.Bytes
	}

	for _, ri := range raw.RecipientInfos {
		var kt keyTransRecipientInfo
		if _, err := asn1.Unmarshal(ri.FullBytes, &kt); err != nil {
			// Другие виды получателей пропускаются: расшифровать
			// сообщение можно и по одному подходящему.
			continue
		}
		var ias issuerAndSerial
		if _, err := asn1.Unmarshal(kt.RID.FullBytes, &ias); err != nil {
			continue
		}
		var transport gostKeyTransport
		if _, err := asn1.Unmarshal(kt.EncryptedKey, &transport); err != nil {
			continue
		}
		ed.Recipients = append(ed.Recipients, &Recipient{
			Issuer:       ias.Issuer,
			SerialNumber: ias.Serial,
			transport:    transport,
			algorithm:    kt.KeyEncryptionAlgorithm,
		})
	}
	if len(ed.Recipients) == 0 {
		return nil, ErrMalformed
	}
	return ed, nil
}

// Decrypt расшифровывает сообщение секретным ключом получателя.
//
// Сертификат нужен, чтобы найти своё место среди адресатов; если он не
// передан, перебираются все.
func (ed *EnvelopedData) Decrypt(priv *gost3410.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	if priv == nil {
		return nil, ErrMalformed
	}
	for _, r := range ed.Recipients {
		if cert != nil {
			if !bytesEqual(r.Issuer.FullBytes, cert.RawIssuer) ||
				cert.SerialNumber.Cmp(r.SerialNumber) != 0 {
				continue
			}
		}
		cek, err := ed.unwrapFor(r, priv)
		if err != nil {
			if cert != nil {
				return nil, err
			}
			continue // без сертификата просто пробуем следующего
		}
		return ed.decryptContent(cek)
	}
	return nil, ErrNoRecipient
}

// unwrapFor восстанавливает ключ шифрования содержимого.
func (ed *EnvelopedData) unwrapFor(r *Recipient, priv *gost3410.PrivateKey) ([]byte, error) {
	tp := r.transport.TransportParameters
	if len(tp.UKM) != keywrap.UKMSize {
		return nil, ErrMalformed
	}
	if len(tp.EphemeralPublicKey.FullBytes) == 0 {
		return nil, ErrMalformed
	}
	// Неявный тег [0] заменяется на SEQUENCE: внутри обычный
	// SubjectPublicKeyInfo.
	spki := append([]byte(nil), tp.EphemeralPublicKey.FullBytes...)
	spki[0] = 0x30
	pub, err := gostasn1.ParsePublicKey(spki)
	if err != nil {
		return nil, err
	}

	kek, err := deriveKEK(priv, pub, tp.UKM)
	if err != nil {
		return nil, err
	}

	sbox, err := gostasn1.SBoxByOID(tp.EncryptionParamSet)
	if err != nil {
		return nil, err
	}

	wrapped := make([]byte, 0, keywrap.WrappedSize)
	wrapped = append(wrapped, tp.UKM...)
	wrapped = append(wrapped, r.transport.SessionEncryptedKey.EncryptedKey...)
	wrapped = append(wrapped, r.transport.SessionEncryptedKey.MACKey...)
	if len(wrapped) != keywrap.WrappedSize {
		return nil, ErrMalformed
	}
	return keywrap.UnwrapCryptoPro(kek, wrapped, sbox)
}

// decryptContent расшифровывает само содержимое.
func (ed *EnvelopedData) decryptContent(cek []byte) ([]byte, error) {
	if len(ed.encrypted) == 0 {
		return nil, ErrNoContent
	}
	st, err := gost28147.NewCFBDecrypterMeshed(cek, ed.sbox, ed.iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ed.encrypted))
	st.XORKeyStream(out, ed.encrypted)
	return out, nil
}

// deriveKEK вырабатывает ключ заворачивания алгоритмом ВКО.
//
// Всегда используется вариант со «Стрибогом» 256: заворачивание ведётся
// ключом ГОСТ 34147-89, а он ровно 32 байта. Разрядность кривой на выбор
// не влияет — ВКО хэширует общую точку, и для 512-битной кривой тоже
// годится. Замечу, что RFC 4490 написан до 2012 года и случай
// 512-битного ключа в нём не оговорён; здесь взято единственное
// сочетание, при котором длины сходятся.
func deriveKEK(priv *gost3410.PrivateKey, pub *gost3410.PublicKey, ukm []byte) ([]byte, error) {
	return vko.KEK256(priv, pub, vko.UKMFromBytes(ukm))
}

// --- формирование ---

// EncryptOptions настраивает зашифрование.
type EncryptOptions struct {
	// ParamSet — набор подстановок ГОСТ 28147-89. Нулевое значение
	// означает id-Gost28147-89-CryptoPro-A-ParamSet, который и
	// применяется на практике.
	ParamSet asn1.ObjectIdentifier
	// ContentType — тип зашифрованного содержимого; по умолчанию id-data.
	ContentType asn1.ObjectIdentifier
}

// Encrypt шифрует content для перечисленных получателей.
//
// Каждому получателю ключ содержимого заворачивается отдельно: для него
// вырабатывается одноразовая пара ключей на его же кривой, и ВКО даёт
// общий ключ заворачивания.
func Encrypt(rand io.Reader, content []byte, recipients []*x509.Certificate, opts *EncryptOptions) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, ErrRecipients
	}
	if opts == nil {
		opts = &EncryptOptions{}
	}
	paramSet := opts.ParamSet
	if paramSet == nil {
		paramSet = gostasn1.OIDCipherCryptoProA
	}
	sbox, err := gostasn1.SBoxByOID(paramSet)
	if err != nil {
		return nil, err
	}
	contentType := opts.ContentType
	if contentType == nil {
		contentType = oidData
	}

	// Ключ шифрования содержимого и синхропосылка.
	cek := make([]byte, gost28147.KeySize)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, err
	}
	iv := make([]byte, gost28147.BlockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}

	st, err := gost28147.NewCFBEncrypterMeshed(cek, sbox, iv)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(content))
	st.XORKeyStream(encrypted, content)

	// Получатели.
	var infos [][]byte
	for _, cert := range recipients {
		ri, err := wrapForRecipient(rand, cek, cert, paramSet, sbox)
		if err != nil {
			return nil, err
		}
		infos = append(infos, ri)
	}

	// EncryptedContentInfo.
	paramsDER, err := asn1.Marshal(gost28147Parameters{IV: iv, EncryptionParamSet: paramSet})
	if err != nil {
		return nil, err
	}
	algDER, err := asn1.Marshal(algorithmIdentifier{
		Algorithm:  oidGost28147,
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	})
	if err != nil {
		return nil, err
	}
	ctDER, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}
	var eci []byte
	eci = append(eci, ctDER...)
	eci = append(eci, algDER...)
	// encryptedContent [0] IMPLICIT OCTET STRING: неявный тег на
	// примитивном типе остаётся примитивным, то есть 0x80, а не 0xA0.
	eci = append(eci, derWrap(0x80, encrypted)...)

	var body []byte
	version, err := asn1.Marshal(0)
	if err != nil {
		return nil, err
	}
	body = append(body, version...)
	body = append(body, derSet(0x31, infos)...)
	body = append(body, derWrap(0x30, eci)...)

	ciType, err := asn1.Marshal(oidEnvelopedData)
	if err != nil {
		return nil, err
	}
	ci := append([]byte(nil), ciType...)
	ci = append(ci, derWrap(0xA0, derWrap(0x30, body))...)
	return derWrap(0x30, ci), nil
}

// wrapForRecipient заворачивает ключ содержимого для одного получателя.
func wrapForRecipient(rand io.Reader, cek []byte, cert *x509.Certificate, paramSet asn1.ObjectIdentifier, sbox *gost28147.SBox) ([]byte, error) {
	pub, err := gostasn1.PublicKeyFromCertificate(cert)
	if err != nil {
		return nil, err
	}

	// Одноразовая пара ключей на кривой получателя.
	eph, err := gost3410.GenerateKey(pub.Curve, rand)
	if err != nil {
		return nil, err
	}
	ukm := make([]byte, keywrap.UKMSize)
	if _, err := io.ReadFull(rand, ukm); err != nil {
		return nil, err
	}

	kek, err := deriveKEK(eph, pub, ukm)
	if err != nil {
		return nil, err
	}
	wrapped, err := keywrap.WrapCryptoPro(kek, ukm, cek, sbox)
	if err != nil {
		return nil, err
	}

	// keyEncryptionAlgorithm повторяет алгоритм открытого ключа
	// получателя вместе с его параметрами (RFC 4490, п. 4.2.1).
	var recipSPKI struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &recipSPKI); err != nil {
		return nil, ErrMalformed
	}

	// Тот же пункт требует, чтобы параметры эфемерного ключа совпадали с
	// параметрами ключа получателя. Совпадения кривой мало: получатель
	// может обозначать её унаследованным идентификатором вроде XchA, а
	// собственная кодировка выбрала бы современный paramSetB. Поэтому
	// алгоритм берётся из сертификата дословно, а от собственной
	// кодировки — только сам ключ.
	ephSPKI, err := gostasn1.MarshalPublicKey(&eph.PublicKey)
	if err != nil {
		return nil, err
	}
	var ephParsed struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(ephSPKI, &ephParsed); err != nil {
		return nil, ErrMalformed
	}
	algBytes, err := asn1.Marshal(recipSPKI.Algorithm)
	if err != nil {
		return nil, err
	}
	keyBytes, err := asn1.Marshal(ephParsed.PublicKey)
	if err != nil {
		return nil, err
	}
	// В GostR3410-TransportParameters ключ идёт с неявным тегом [0].
	implicitSPKI := derWrap(0xA0, append(append([]byte(nil), algBytes...), keyBytes...))

	transport := gostKeyTransport{
		SessionEncryptedKey: gost28147EncryptedKey{
			EncryptedKey: wrapped[keywrap.UKMSize : keywrap.UKMSize+gost28147.KeySize],
			MACKey:       wrapped[keywrap.UKMSize+gost28147.KeySize:],
		},
		TransportParameters: gostTransportParameters{
			EncryptionParamSet: paramSet,
			EphemeralPublicKey: asn1.RawValue{FullBytes: implicitSPKI},
			UKM:                ukm,
		},
	}
	transportDER, err := asn1.Marshal(transport)
	if err != nil {
		return nil, err
	}

	sid, err := asn1.Marshal(issuerAndSerial{
		Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
		Serial: cert.SerialNumber,
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(keyTransRecipientInfo{
		Version:                0,
		RID:                    asn1.RawValue{FullBytes: sid},
		KeyEncryptionAlgorithm: recipSPKI.Algorithm,
		EncryptedKey:           transportDER,
	})
}
