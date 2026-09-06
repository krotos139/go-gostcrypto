// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pfx

import (
	"crypto/x509"
	"encoding/asn1"
	"io"

	"github.com/krotos139/go-gostcrypto/cms"
	"github.com/krotos139/go-gostcrypto/gost3410"
)

// Защита контейнера ключом отправителя — раздел 6 Р 50.1.112-2016.
//
// Отличий от парольной защиты два, и оба следуют из того, что общего
// секрета у сторон нет:
//
//   - разделы шифруются не паролем, а на открытом ключе получателя:
//     каждый раздел становится зашифрованным сообщением CMS, а ключ
//     согласуется алгоритмом ВКО;
//   - целостность подтверждается не имитовставкой, а подписью
//     отправителя: authSafe становится подписанным сообщением CMS, а
//     поле macData отсутствует вовсе.
//
// Ключ при этом лежит в обычном портфеле keyBag: отдельно шифровать его
// нечем и незачем — раздел уже зашифрован (п. 7 рекомендаций).
//
// # Чем этот способ проверен
//
// Контрольного примера для него в рекомендациях нет, настоящих таких
// контейнеров тоже не нашлось. Поэтому проверка здесь слабее, чем у
// парольного варианта: сходимость с самой собой и соответствие тексту
// стандарта, но не совместимость с чужими реализациями. Парольный
// вариант, для сравнения, сверен с контрольным примером стандарта и с
// КриптоПро.
//
// Стандарт называет парольную защиту «наиболее приемлемой для
// большинства практических приложений» (п. 5); этот способ применяйте,
// когда общего пароля у сторон нет.

// Recipient — получатель контейнера: его ключ и сертификат.
//
// Сертификат нужен, чтобы найти свою запись среди адресатов; передайте
// тот же, на который контейнер зашифрован.
type Recipient struct {
	Key         *gost3410.PrivateKey
	Certificate *x509.Certificate
}

// Sender — отправитель, подписывающий контейнер.
type Sender struct {
	Key         *gost3410.PrivateKey
	Certificate *x509.Certificate
}

// ParseWithKey разбирает контейнер, защищённый ключом отправителя
// (раздел 6 рекомендаций), и проверяет подпись под ним.
//
// Это соответствие Parse: там пароль, здесь ключ получателя.
func ParseWithKey(der []byte, to *Recipient) (*Container, error) {
	if to == nil || to.Key == nil {
		return nil, ErrNoKey
	}
	p, err := parseHeader(der)
	if err != nil {
		return nil, err
	}
	// Вид контейнера определяется первым: иначе парольный контейнер
	// отбраковывался бы по отсутствующему у него признаку, и сообщение
	// об ошибке уводило бы в сторону.
	var ci contentInfo
	if _, err := asn1.Unmarshal(p.AuthSafe.FullBytes, &ci); err != nil {
		return nil, ErrMalformed
	}
	if !ci.ContentType.Equal(oidSignedData) {
		// Контейнер под парольной защитой: для него есть Parse.
		return nil, ErrUnsupported
	}
	// При защите подписью поля macData быть не должно (п. 7).
	if len(p.MacData.Mac.Digest) > 0 {
		return nil, ErrMalformed
	}

	sd, err := cms.Parse(p.AuthSafe.FullBytes)
	if err != nil {
		return nil, err
	}
	if sd.Detached || len(sd.Content) == 0 {
		return nil, ErrMalformed
	}
	// Целостность проверяется до того, как содержимое пойдёт в разбор.
	if err := sd.Verify(nil); err != nil {
		return nil, err
	}

	c := &Container{}
	for _, s := range sd.Signers {
		if s.Certificate != nil {
			c.Signers = append(c.Signers, s.Certificate)
		}
	}
	if err := c.readSections(sd.Content, &opener{recipient: to}); err != nil {
		return nil, err
	}
	return c, nil
}

// DecodeWithKey разбирает контейнер и возвращает первый ключ вместе с
// соответствующим ему сертификатом.
//
// Это соответствие Decode.
func DecodeWithKey(der []byte, to *Recipient) (*gost3410.PrivateKey, *x509.Certificate, error) {
	c, err := ParseWithKey(der, to)
	if err != nil {
		return nil, nil, err
	}
	if len(c.Keys) == 0 {
		return nil, nil, ErrNoKey
	}
	key := c.Keys[0]
	return key.Key, c.CertificateFor(key), nil
}

// MarshalWithKey собирает контейнер, защищённый ключом отправителя.
//
// Это соответствие Marshal: там пароль, здесь сертификаты получателей и
// ключ отправителя. Аргументы priv и certs означают то же самое — ключ и
// сертификаты, которые кладутся в контейнер.
//
// Разделы шифруются каждому получателю отдельно; целостность
// подтверждается подписью отправителя.
func MarshalWithKey(rnd io.Reader, priv *gost3410.PrivateKey, certs []*x509.Certificate, to []*x509.Certificate, from *Sender, opts *MarshalOptions) ([]byte, error) {
	if priv == nil {
		return nil, ErrNoKey
	}
	if len(to) == 0 {
		return nil, ErrNoRecipients
	}
	if from == nil || from.Key == nil || from.Certificate == nil {
		return nil, ErrNoSender
	}
	if opts == nil {
		opts = &MarshalOptions{}
	}

	localKeyID := opts.LocalKeyID
	if len(localKeyID) == 0 {
		localKeyID = make([]byte, 20)
		if _, err := io.ReadFull(rnd, localKeyID); err != nil {
			return nil, err
		}
	}

	// Ключ в обычном портфеле: раздел целиком уже будет зашифрован.
	keyDER, err := pkcs8MarshalPlain(priv, opts)
	if err != nil {
		return nil, err
	}
	keyBagDER, err := marshalBag(oidKeyBag, keyDER, localKeyID)
	if err != nil {
		return nil, err
	}
	keySection, err := cms.Encrypt(rnd, derWrap(0x30, keyBagDER), to, nil)
	if err != nil {
		return nil, err
	}
	sections := [][]byte{keySection}

	if len(certs) > 0 {
		bags, err := marshalCertBags(certs, localKeyID)
		if err != nil {
			return nil, err
		}
		var section []byte
		if opts.PlainCertificates {
			section, err = marshalDataSection(bags)
		} else {
			section, err = cms.Encrypt(rnd, bags, to, nil)
		}
		if err != nil {
			return nil, err
		}
		sections = append(sections, section)
	}

	authSafe := derWrap(0x30, concat(sections...))

	// Подпись отправителя заменяет имитовставку; macData отсутствует.
	signed, err := cms.Sign(rnd, authSafe, from.Certificate, from.Key, &cms.SignOptions{
		SigningTime: opts.SigningTime,
	})
	if err != nil {
		return nil, err
	}

	versionDER, err := asn1.Marshal(3)
	if err != nil {
		return nil, err
	}
	return derWrap(0x30, concat(versionDER, signed)), nil
}
