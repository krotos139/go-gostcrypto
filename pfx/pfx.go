// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

// Package pfx читает и собирает транспортные ключевые контейнеры
// PKCS#12 по правилам Р 50.1.112-2016.
//
// Это формат файлов .pfx и .p12: в одном файле лежат ключ подписи и
// сопутствующие сертификаты, а всё вместе закрыто паролем.
//
// # Устройство
//
// Контейнер состоит из разделов (AuthenticatedSafe), каждый из которых
// либо открытый, либо зашифрован на пароле. Внутри разделов лежат
// портфели (SafeBag): с ключом, с зашифрованным ключом, с сертификатом.
// Целостность всего контейнера подтверждается имитовставкой
// HMAC_GOSTR3411_2012_512, ключ для которой тоже выводится из пароля.
//
// Ключ для имитовставки берётся не обычным образом: PBKDF2 вырабатывает
// 96 байт, а ключом становятся последние 32 из них (п. 5 рекомендаций).
//
// # Что поддерживается
//
// Парольная защита — раздел 5 рекомендаций: чтение и сборка. Разделы,
// зашифрованные на открытом ключе (раздел 6), при разборе распознаются,
// но не расшифровываются: для этого нужен закрытый ключ получателя,
// а такой контейнер собирается через пакет cms.
package pfx

import (
	"crypto/hmac"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/krotos139/go-gostcrypto/cms"
	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/kdf"
	"github.com/krotos139/go-gostcrypto/mac"
	"github.com/krotos139/go-gostcrypto/pkcs8"
)

// Идентификаторы из PKCS#7, PKCS#9 и PKCS#12.
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Certificate     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}

	oidFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

var (
	// ErrMalformed возвращается при некорректной структуре контейнера.
	ErrMalformed = errors.New("pfx: некорректная структура контейнера")
	// ErrUnsupported возвращается для неподдерживаемого варианта.
	ErrUnsupported = errors.New("pfx: неподдерживаемый вариант контейнера")
	// ErrMAC возвращается, если имитовставка не сошлась: пароль не тот
	// либо контейнер изменён.
	ErrMAC = errors.New("pfx: имитовставка контейнера не совпала")
	// ErrNoKey возвращается, если в контейнере нет ключа подписи.
	ErrNoKey = errors.New("pfx: в контейнере нет ключа подписи")
	// ErrNoMAC возвращается, если контейнер не защищён имитовставкой.
	ErrNoMAC = errors.New("pfx: контейнер не содержит имитовставки")
	// ErrNoRecipients возвращается, если не указан ни один получатель.
	ErrNoRecipients = errors.New("pfx: не указан ни один получатель")
	// ErrNoSender возвращается, если не указан ключ отправителя.
	ErrNoSender = errors.New("pfx: не указан ключ отправителя")
)

// MACKeySize — длина ключа имитовставки.
const MACKeySize = 32

// macDerivedSize — сколько байт вырабатывает PBKDF2 для имитовставки;
// ключом служат последние MACKeySize из них.
const macDerivedSize = 96

// --- структуры ASN.1 ---

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type digestInfo struct {
	Algorithm pkcs8.AlgorithmIdentifier
	Digest    []byte
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type pfxASN1 struct {
	Version int
	// AuthSafe хранится сырым: при защите подписью его байты целиком
	// уходят в пакет cms как подписанное сообщение.
	AuthSafe asn1.RawValue
	MacData  macData `asn1:"optional"`
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkcs8.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type safeBag struct {
	BagID         asn1.ObjectIdentifier
	BagValue      asn1.RawValue `asn1:"explicit,tag:0"`
	BagAttributes []pkcs12Attr  `asn1:"set,optional"`
}

type pkcs12Attr struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type certBagASN1 struct {
	CertID    asn1.ObjectIdentifier
	CertValue asn1.RawValue `asn1:"explicit,tag:0"`
}

// --- разбор ---

// Container — разобранный контейнер.
type Container struct {
	// Keys — ключи подписи, найденные в контейнере.
	Keys []*KeyEntry
	// Certificates — сертификаты из контейнера.
	Certificates []*CertEntry
	// HasMAC сообщает, была ли проверена имитовставка. Ложь означает,
	// что целостность подтверждена не ей, а подписью, либо не
	// подтверждена вовсе.
	HasMAC bool
	// Signers — сертификаты, чьей подписью подтверждена целостность
	// контейнера (раздел 6 рекомендаций). Пусто при парольной защите.
	//
	// Подпись проверена математически; доверие к сертификату остаётся
	// за вызывающим кодом, как и везде в этой библиотеке.
	Signers []*x509.Certificate
	// SkippedSections — число разделов, которые не удалось прочитать:
	// зашифрованные на открытом ключе либо неизвестного вида.
	SkippedSections int
}

// KeyEntry — ключ вместе с сопутствующими сведениями.
type KeyEntry struct {
	Key *gost3410.PrivateKey
	// LocalKeyID связывает ключ с сертификатом: у пары значение общее.
	LocalKeyID []byte
	// FriendlyName — необязательное имя, показываемое пользователю.
	FriendlyName string
	// Encrypted сообщает, что ключ лежал зашифрованным отдельно от
	// раздела (портфель pkcs8ShroudedKeyBag).
	Encrypted bool
}

// CertEntry — сертификат вместе с сопутствующими сведениями.
type CertEntry struct {
	Certificate  *x509.Certificate
	LocalKeyID   []byte
	FriendlyName string
}

// macKey вырабатывает ключ имитовставки: последние 32 байта из 96,
// выработанных PBKDF2 (п. 5 Р 50.1.112-2016).
func macKey(password, salt []byte, iterations int) []byte {
	full := kdf.PBKDF2(password, salt, iterations, macDerivedSize)
	return full[macDerivedSize-MACKeySize:]
}

// opener знает, как раскрывать разделы контейнера: паролем либо ключом
// получателя. Оба способа описаны в Р 50.1.112-2016, разделы 5 и 6.
type opener struct {
	password  []byte
	recipient *Recipient
}

// Parse разбирает контейнер под парольной защитой (раздел 5
// рекомендаций) и проверяет его целостность.
//
// Пароль передаётся в кодировке UTF-8 без завершающего нуля. Если
// имитовставка не сходится, возвращается ErrMAC: разбирать содержимое
// контейнера с неподтверждённой целостностью незачем.
func Parse(der, password []byte) (*Container, error) {
	p, err := parseHeader(der)
	if err != nil {
		return nil, err
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(p.AuthSafe.FullBytes, &ci); err != nil {
		return nil, ErrMalformed
	}
	if !ci.ContentType.Equal(oidData) {
		// Целостность подтверждается подписью отправителя: это другой
		// способ защиты, для него есть ParseWithKey.
		return nil, ErrUnsupported
	}
	var authSafe []byte
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &authSafe); err != nil {
		return nil, ErrMalformed
	}

	c := &Container{}
	// Имитовставка считается от содержимого поля content структуры
	// authSafe, то есть от кодирования AuthenticatedSafe.
	if len(p.MacData.Mac.Digest) > 0 {
		if err := checkMAC(p.MacData, authSafe, password); err != nil {
			return nil, err
		}
		c.HasMAC = true
	}

	if err := c.readSections(authSafe, &opener{password: password}); err != nil {
		return nil, err
	}
	return c, nil
}

// parseHeader разбирает внешнюю оболочку контейнера.
func parseHeader(der []byte) (*pfxASN1, error) {
	var p pfxASN1
	if rest, err := asn1.Unmarshal(der, &p); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if p.Version != 3 {
		return nil, ErrUnsupported
	}
	return &p, nil
}

// readSections проходит по разделам AuthenticatedSafe.
func (c *Container) readSections(authSafe []byte, o *opener) error {
	var safes []asn1.RawValue
	if _, err := asn1.Unmarshal(authSafe, &safes); err != nil {
		return ErrMalformed
	}
	for _, raw := range safes {
		bags, err := sectionBags(raw, o)
		if err != nil {
			if err == ErrUnsupported {
				c.SkippedSections++
				continue
			}
			return err
		}
		if err := c.addBags(bags, o.password); err != nil {
			return err
		}
	}
	return nil
}

func checkMAC(md macData, content, password []byte) error {
	if !md.Mac.Algorithm.Algorithm.Equal(gostasn1.OIDDigest512) {
		return ErrUnsupported
	}
	iterations := md.Iterations
	if iterations <= 0 {
		iterations = 1
	}
	got := mac.Sum512(macKey(password, md.MacSalt, iterations), content)
	if !hmac.Equal(got, md.Mac.Digest) {
		return ErrMAC
	}
	return nil
}

// sectionBags возвращает портфели одного раздела.
func sectionBags(rawSection asn1.RawValue, o *opener) ([]safeBag, error) {
	var s contentInfo
	if _, err := asn1.Unmarshal(rawSection.FullBytes, &s); err != nil {
		return nil, ErrMalformed
	}

	var raw []byte
	switch {
	case s.ContentType.Equal(oidData):
		if _, err := asn1.Unmarshal(s.Content.Bytes, &raw); err != nil {
			return nil, ErrMalformed
		}

	case s.ContentType.Equal(oidEncryptedData):
		if o.password == nil {
			return nil, ErrUnsupported
		}
		var ed encryptedData
		if _, err := asn1.Unmarshal(s.Content.Bytes, &ed); err != nil {
			return nil, ErrMalformed
		}
		if len(ed.EncryptedContentInfo.EncryptedContent.Bytes) == 0 {
			return nil, ErrMalformed
		}
		plain, err := pkcs8.DecryptPBES2(
			ed.EncryptedContentInfo.ContentEncryptionAlgorithm,
			ed.EncryptedContentInfo.EncryptedContent.Bytes, o.password)
		if err != nil {
			return nil, err
		}
		raw = plain

	case s.ContentType.Equal(oidEnvelopedData):
		// Раздел зашифрован на открытом ключе получателя: раскрыть его
		// можно только его секретным ключом.
		if o.recipient == nil {
			return nil, ErrUnsupported
		}
		ed, err := cms.ParseEnvelopedData(rawSection.FullBytes)
		if err != nil {
			return nil, err
		}
		plain, err := ed.Decrypt(o.recipient.Key, o.recipient.Certificate)
		if err != nil {
			return nil, err
		}
		raw = plain

	default:
		return nil, ErrUnsupported
	}

	var bags []safeBag
	if _, err := asn1.Unmarshal(raw, &bags); err != nil {
		return nil, ErrMalformed
	}
	return bags, nil
}

// attrValues достаёт значения атрибутов портфеля.
func attrValues(attrs []pkcs12Attr) (localKeyID []byte, friendlyName string) {
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidLocalKeyID):
			var v []byte
			if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err == nil {
				localKeyID = v
			}
		case a.Type.Equal(oidFriendlyName):
			var v string
			if _, err := asn1.UnmarshalWithParams(a.Values.Bytes, &v, "bmp"); err == nil {
				friendlyName = v
			}
		}
	}
	return localKeyID, friendlyName
}

func (c *Container) addBags(bags []safeBag, password []byte) error {
	for _, b := range bags {
		id, name := attrValues(b.BagAttributes)
		switch {
		case b.BagID.Equal(oidKeyBag):
			key, err := pkcs8.ParsePrivateKey(b.BagValue.Bytes)
			if err != nil {
				return err
			}
			c.Keys = append(c.Keys, &KeyEntry{Key: key, LocalKeyID: id, FriendlyName: name})

		case b.BagID.Equal(oidPKCS8ShroudedKeyBag):
			key, err := pkcs8.ParseEncryptedPrivateKey(b.BagValue.Bytes, password)
			if err != nil {
				return err
			}
			c.Keys = append(c.Keys, &KeyEntry{
				Key: key, LocalKeyID: id, FriendlyName: name, Encrypted: true,
			})

		case b.BagID.Equal(oidCertBag):
			var cb certBagASN1
			if _, err := asn1.Unmarshal(b.BagValue.Bytes, &cb); err != nil {
				return ErrMalformed
			}
			if !cb.CertID.Equal(oidX509Certificate) {
				continue // сертификаты иных видов пропускаются
			}
			var der []byte
			if _, err := asn1.Unmarshal(cb.CertValue.Bytes, &der); err != nil {
				return ErrMalformed
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return err
			}
			c.Certificates = append(c.Certificates, &CertEntry{
				Certificate: cert, LocalKeyID: id, FriendlyName: name,
			})
		}
		// Портфели иных видов молча пропускаются.
	}
	return nil
}

// Decode разбирает контейнер и возвращает первый ключ вместе с
// соответствующим ему сертификатом.
//
// Соответствие устанавливается по атрибуту localKeyId, а если его нет —
// по совпадению открытого ключа. Если сертификата для ключа не нашлось,
// возвращается только ключ.
func Decode(der, password []byte) (*gost3410.PrivateKey, *x509.Certificate, error) {
	c, err := Parse(der, password)
	if err != nil {
		return nil, nil, err
	}
	if len(c.Keys) == 0 {
		return nil, nil, ErrNoKey
	}
	key := c.Keys[0]
	return key.Key, c.CertificateFor(key), nil
}

// CertificateFor находит сертификат, соответствующий ключу.
func (c *Container) CertificateFor(key *KeyEntry) *x509.Certificate {
	if key == nil {
		return nil
	}
	// Сначала по метке, связывающей пару.
	if len(key.LocalKeyID) > 0 {
		for _, ce := range c.Certificates {
			if len(ce.LocalKeyID) > 0 && string(ce.LocalKeyID) == string(key.LocalKeyID) {
				return ce.Certificate
			}
		}
	}
	// Затем по самому ключу: это надёжнее метки, но дороже.
	for _, ce := range c.Certificates {
		pub, err := gostasn1.PublicKeyFromCertificate(ce.Certificate)
		if err != nil {
			continue
		}
		if pub.Equal(&key.Key.PublicKey) {
			return ce.Certificate
		}
	}
	return nil
}
