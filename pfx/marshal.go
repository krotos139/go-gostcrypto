// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pfx

import (
	"crypto/x509"
	"encoding/asn1"
	"io"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/mac"
	"github.com/krotos139/go-gostcrypto/pkcs8"
)

// derLen дописывает длину в кодировке DER.
func derLen(out []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(out, byte(n))
	case n < 0x100:
		return append(out, 0x81, byte(n))
	case n < 0x10000:
		return append(out, 0x82, byte(n>>8), byte(n))
	case n < 0x1000000:
		return append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// derWrap заворачивает содержимое в элемент DER с заданным тегом.
func derWrap(tag byte, body []byte) []byte {
	return append(derLen([]byte{tag}, len(body)), body...)
}

// MarshalOptions настраивает сборку контейнера.
type MarshalOptions struct {
	// Iterations — число итераций PBKDF2 для всех парольных операций.
	// Ноль означает pkcs8.DefaultIterations.
	Iterations int
	// PlainCertificates оставляет сертификаты незашифрованными.
	//
	// По умолчанию они шифруются: п. 4.2 рекомендаций замечает, что по
	// сертификату видно владельца ключа, и это облегчает разбор
	// перехваченного контейнера.
	PlainCertificates bool
	// KeyOptions настраивает шифрование самого ключа, в том числе
	// маскирование.
	KeyOptions *pkcs8.EncryptOptions
	// LocalKeyID связывает ключ с его сертификатом. Пустое значение
	// означает случайную метку.
	LocalKeyID []byte
	// SigningTime добавляется в подпись контейнера, защищённого ключом
	// отправителя. Нулевое значение — атрибут не добавляется.
	//
	// Парольную сборку не затрагивает: там целостность подтверждается
	// имитовставкой, а не подписью.
	SigningTime time.Time
}

// pkcs8MarshalPlain кодирует ключ без шифрования: он нужен портфелю
// keyBag, который защищён шифрованием всего раздела.
func pkcs8MarshalPlain(priv *gost3410.PrivateKey, opts *MarshalOptions) ([]byte, error) {
	var mo *pkcs8.MarshalOptions
	if opts != nil && opts.KeyOptions != nil {
		mo = opts.KeyOptions.Marshal
	}
	return pkcs8.MarshalPrivateKey(priv, mo)
}

// marshalCertBags собирает SafeContents из портфелей с сертификатами.
//
// Метку localKeyId получает только первый: он и считается парным ключу.
func marshalCertBags(certs []*x509.Certificate, localKeyID []byte) ([]byte, error) {
	var bags []byte
	for i, cert := range certs {
		// Собирается вручную: asn1.Marshal для RawValue с заполненным
		// FullBytes выводит его как есть и явный тег [0] не добавляет.
		certIDDER, err := asn1.Marshal(oidX509Certificate)
		if err != nil {
			return nil, err
		}
		cb := derWrap(0x30, concat(certIDDER, derWrap(0xA0, mustOctetString(cert.Raw))))

		var id []byte
		if i == 0 {
			id = localKeyID
		}
		bag, err := marshalBag(oidCertBag, cb, id)
		if err != nil {
			return nil, err
		}
		bags = append(bags, bag...)
	}
	return derWrap(0x30, bags), nil
}

// Marshal собирает транспортный ключевой контейнер.
//
// Ключ кладётся в портфель pkcs8ShroudedKeyBag, зашифрованный отдельно;
// сертификаты — в раздел, зашифрованный на том же пароле, но с иной
// солью, как того требует п. 4.2 рекомендаций. Целостность всего
// контейнера подтверждается имитовставкой.
//
// Первым в certs должен идти сертификат, соответствующий ключу: именно
// он получает общую с ключом метку localKeyId.
func Marshal(rnd io.Reader, priv *gost3410.PrivateKey, certs []*x509.Certificate, password []byte, opts *MarshalOptions) ([]byte, error) {
	if priv == nil {
		return nil, ErrNoKey
	}
	if opts == nil {
		opts = &MarshalOptions{}
	}
	iterations := opts.Iterations
	if iterations == 0 {
		iterations = pkcs8.DefaultIterations
	}

	localKeyID := opts.LocalKeyID
	if len(localKeyID) == 0 {
		localKeyID = make([]byte, 20)
		if _, err := io.ReadFull(rnd, localKeyID); err != nil {
			return nil, err
		}
	}

	// Раздел с ключом: сам портфель зашифрован, раздел — нет.
	keyOpts := opts.KeyOptions
	if keyOpts == nil {
		keyOpts = &pkcs8.EncryptOptions{Iterations: iterations}
	}
	shrouded, err := pkcs8.MarshalEncryptedPrivateKey(rnd, priv, password, keyOpts)
	if err != nil {
		return nil, err
	}
	keyBagDER, err := marshalBag(oidPKCS8ShroudedKeyBag, shrouded, localKeyID)
	if err != nil {
		return nil, err
	}
	keySection, err := marshalDataSection(derWrap(0x30, keyBagDER))
	if err != nil {
		return nil, err
	}

	sections := [][]byte{keySection}

	// Раздел с сертификатами.
	if len(certs) > 0 {
		safeContents, err := marshalCertBags(certs, localKeyID)
		if err != nil {
			return nil, err
		}
		var section []byte
		if opts.PlainCertificates {
			section, err = marshalDataSection(safeContents)
		} else {
			section, err = marshalEncryptedSection(rnd, safeContents, password, iterations, keyOpts)
		}
		if err != nil {
			return nil, err
		}
		sections = append(sections, section)
	}

	authSafe := derWrap(0x30, concat(sections...))

	// Имитовставка считается от кодирования AuthenticatedSafe.
	macSalt := make([]byte, 32)
	if _, err := io.ReadFull(rnd, macSalt); err != nil {
		return nil, err
	}
	digest := mac.Sum512(macKey(password, macSalt, iterations), authSafe)

	macDER, err := asn1.Marshal(macData{
		Mac: digestInfo{
			Algorithm: pkcs8.AlgorithmIdentifier{Algorithm: gostasn1.OIDDigest512},
			Digest:    digest,
		},
		MacSalt:    macSalt,
		Iterations: iterations,
	})
	if err != nil {
		return nil, err
	}

	// authSafe как ContentInfo типа data.
	ctDER, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}
	authSafeCI := derWrap(0x30, concat(ctDER, derWrap(0xA0, mustOctetString(authSafe))))

	versionDER, err := asn1.Marshal(3)
	if err != nil {
		return nil, err
	}
	return derWrap(0x30, concat(versionDER, authSafeCI, macDER)), nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// mustOctetString кодирует байты в OCTET STRING.
func mustOctetString(b []byte) []byte {
	return derWrap(0x04, b)
}

// marshalBag собирает SafeBag с необязательной меткой localKeyId.
func marshalBag(bagID asn1.ObjectIdentifier, value []byte, localKeyID []byte) ([]byte, error) {
	idDER, err := asn1.Marshal(bagID)
	if err != nil {
		return nil, err
	}
	body := concat(idDER, derWrap(0xA0, value))

	if len(localKeyID) > 0 {
		attr, err := asn1.Marshal(pkcs12Attr{
			Type: oidLocalKeyID,
			Values: asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSet,
				IsCompound: true,
				Bytes:      mustOctetString(localKeyID),
			},
		})
		if err != nil {
			return nil, err
		}
		body = append(body, derWrap(0x31, attr)...)
	}
	return derWrap(0x30, body), nil
}

// marshalDataSection заворачивает содержимое в ContentInfo типа data.
func marshalDataSection(safeContents []byte) ([]byte, error) {
	ctDER, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}
	return derWrap(0x30, concat(ctDER, derWrap(0xA0, mustOctetString(safeContents)))), nil
}

// marshalEncryptedSection заворачивает содержимое в ContentInfo типа
// encryptedData, зашифрованный на пароле.
func marshalEncryptedSection(rnd io.Reader, safeContents, password []byte, iterations int, keyOpts *pkcs8.EncryptOptions) ([]byte, error) {
	// Соль здесь своя: п. 4.2 требует разных синхропосылок для разных
	// разделов, иначе один и тот же ключ шифровал бы их все.
	encOpts := &pkcs8.EncryptOptions{
		Iterations: iterations,
		SaltSize:   32,
	}
	if keyOpts != nil {
		encOpts.ParamSet = keyOpts.ParamSet
	}
	alg, encrypted, err := pkcs8.EncryptPBES2(rnd, safeContents, password, encOpts)
	if err != nil {
		return nil, err
	}

	algDER, err := asn1.Marshal(alg)
	if err != nil {
		return nil, err
	}
	dataOID, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}
	// encryptedContent [0] IMPLICIT OCTET STRING: неявный тег на
	// примитивном типе остаётся примитивным.
	eci := derWrap(0x30, concat(dataOID, algDER, derWrap(0x80, encrypted)))

	versionDER, err := asn1.Marshal(0)
	if err != nil {
		return nil, err
	}
	ed := derWrap(0x30, concat(versionDER, eci))

	ctDER, err := asn1.Marshal(oidEncryptedData)
	if err != nil {
		return nil, err
	}
	return derWrap(0x30, concat(ctDER, derWrap(0xA0, ed))), nil
}
