// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// Метка времени по RFC 3161 и профиль CAdES-T.
//
// Атрибут signingTime — заявление подписанта: он лежит среди подписанных
// атрибутов и подделывается вместе со всей подписью. Метка времени
// устроена иначе: службу штампов времени просят подписать хэш от
// значения подписи, и её ответ кладут в неподписанные атрибуты. Получаем
// свидетельство независимой стороны о том, что подпись существовала не
// позже указанного момента.
//
// Что здесь есть: сборка запроса, разбор ответа, разбор и проверка
// токена, встраивание метки при подписании. Чего нет: обращения к службе
// по сети (это дело вызывающего кода) и добавления метки к уже готовой
// подписи.

var (
	// oidSignatureTimeStamp — id-aa-signatureTimeStampToken, неподписанный
	// атрибут с меткой времени (RFC 3161, приложение A).
	oidSignatureTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	// OIDContentTypeTSTInfo — id-ct-TSTInfo, тип содержимого токена метки.
	OIDContentTypeTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

var (
	// ErrTimestampImprint возвращается, если метка времени выдана не на
	// эту подпись.
	ErrTimestampImprint = errors.New("cms: метка времени не соответствует подписи")
	// ErrTimestampStatus возвращается, если служба отказала в выдаче.
	ErrTimestampStatus = errors.New("cms: служба штампов времени отказала")
	// ErrNoTimestamp возвращается, если метки времени в подписи нет.
	ErrNoTimestamp = errors.New("cms: метка времени отсутствует")
)

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tstAccuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time       `asn1:"generalized"`
	Accuracy       tstAccuracy     `asn1:"optional"`
	Ordering       bool            `asn1:"optional,default:false"`
	Nonce          *big.Int        `asn1:"optional"`
	TSA            asn1.RawValue   `asn1:"optional,tag:0"`
	Extensions     []asn1.RawValue `asn1:"optional,tag:1"`
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"optional,tag:0"`
}

// PKIStatusInfo разбирается вручную: statusString и failInfo
// необязательны, а необязательный RawValue в encoding/asn1 захватывает
// первое, что попадётся. Нужен здесь только код состояния.
type timeStampResp struct {
	Status         asn1.RawValue
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// pkiStatus достаёт код состояния: он идёт первым элементом.
func pkiStatus(raw asn1.RawValue) (int, error) {
	elems, err := derElements(raw.Bytes)
	if err != nil || len(elems) == 0 {
		return 0, ErrMalformed
	}
	var status int
	if _, err := asn1.Unmarshal(elems[0], &status); err != nil {
		return 0, ErrMalformed
	}
	return status, nil
}

// Timestamp — разобранная метка времени.
type Timestamp struct {
	// GenTime — момент, который засвидетельствовала служба.
	GenTime time.Time
	// Accuracy — заявленная точность; ноль, если не указана.
	Accuracy time.Duration
	// SerialNumber — номер метки у службы.
	SerialNumber *big.Int
	// Policy — политика службы штампов времени.
	Policy asn1.ObjectIdentifier
	// Nonce — значение из запроса, если служба его вернула.
	Nonce *big.Int
	// Certificates — сертификаты, вложенные в токен.
	Certificates []*x509.Certificate
	// Signers — подписанты токена, то есть сама служба.
	Signers []*Signer

	token   *SignedData
	imprint messageImprint
	raw     []byte
}

// Raw возвращает токен в исходной кодировке DER.
func (t *Timestamp) Raw() []byte { return t.raw }

// ParseTimestampToken разбирает токен метки времени: подписанное
// сообщение с содержимым типа id-ct-TSTInfo.
func ParseTimestampToken(der []byte) (*Timestamp, error) {
	sd, err := Parse(der)
	if err != nil {
		return nil, err
	}
	if !sd.ContentType.Equal(OIDContentTypeTSTInfo) {
		return nil, ErrUnsupported
	}
	if sd.Detached {
		// TSTInfo обязана быть встроена: без неё проверять нечего.
		return nil, ErrMalformed
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(sd.Content, &info); err != nil {
		return nil, ErrMalformed
	}

	t := &Timestamp{
		GenTime:      info.GenTime,
		SerialNumber: info.SerialNumber,
		Policy:       info.Policy,
		Nonce:        info.Nonce,
		Certificates: sd.Certificates,
		Signers:      sd.Signers,
		token:        sd,
		imprint:      info.MessageImprint,
		raw:          append([]byte(nil), der...),
	}
	t.Accuracy = time.Duration(info.Accuracy.Seconds)*time.Second +
		time.Duration(info.Accuracy.Millis)*time.Millisecond +
		time.Duration(info.Accuracy.Micros)*time.Microsecond
	return t, nil
}

// Verify проверяет метку времени над данными data.
//
// Для метки на подпись data — это значение поля signature из SignerInfo,
// то есть то, что возвращает Signer.SignatureValue.
//
// Проверяются две вещи: что хэш в метке соответствует data и что подпись
// службы под самой меткой верна. Доверие к сертификату службы, как и
// везде в этом пакете, остаётся за вызывающим кодом.
func (t *Timestamp) Verify(data []byte) error {
	want, err := digest(t.imprint.HashAlgorithm, data)
	if err != nil {
		return err
	}
	if !bytesEqual(want, t.imprint.HashedMessage) {
		return ErrTimestampImprint
	}
	return t.token.Verify(nil)
}

// ParseTimestampResponse разбирает ответ службы штампов времени.
func ParseTimestampResponse(der []byte) (*Timestamp, error) {
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, ErrMalformed
	}
	status, err := pkiStatus(resp.Status)
	if err != nil {
		return nil, err
	}
	// 0 - выдано, 1 - выдано с оговорками; всё прочее означает отказ.
	if status != 0 && status != 1 {
		return nil, ErrTimestampStatus
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, ErrMalformed
	}
	return ParseTimestampToken(resp.TimeStampToken.FullBytes)
}

// TimestampRequestOptions настраивает запрос к службе штампов времени.
type TimestampRequestOptions struct {
	// Policy — требуемая политика службы; необязательно.
	Policy asn1.ObjectIdentifier
	// Nonce защищает от повтора чужого ответа: служба обязана вернуть
	// то же значение. Нулевое значение — поле не добавляется.
	Nonce *big.Int
	// RequestCertificate просит службу вложить в токен свой сертификат.
	RequestCertificate bool
}

// NewTimestampRequest собирает запрос к службе штампов времени на хэш
// digest, вычисленный алгоритмом digestOID.
func NewTimestampRequest(digestValue []byte, digestOID asn1.ObjectIdentifier, opts *TimestampRequestOptions) ([]byte, error) {
	if opts == nil {
		opts = &TimestampRequestOptions{}
	}
	if len(digestValue) == 0 || len(digestOID) == 0 {
		return nil, ErrMalformed
	}
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{Algorithm: digestOID},
			HashedMessage: digestValue,
		},
		ReqPolicy: opts.Policy,
		Nonce:     opts.Nonce,
		CertReq:   opts.RequestCertificate,
	}
	return asn1.Marshal(req)
}

// MarshalTSTInfo собирает содержимое токена метки времени.
//
// Нужна тем, кто сам выступает службой штампов времени: полученную
// структуру подписывают через Sign с ContentType = OIDContentTypeTSTInfo.
func MarshalTSTInfo(digestValue []byte, digestOID asn1.ObjectIdentifier, policy asn1.ObjectIdentifier, serial *big.Int, genTime time.Time, nonce *big.Int) ([]byte, error) {
	if len(digestValue) == 0 || len(digestOID) == 0 || serial == nil {
		return nil, ErrMalformed
	}
	info := tstInfo{
		Version: 1,
		Policy:  policy,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{Algorithm: digestOID},
			HashedMessage: digestValue,
		},
		SerialNumber: serial,
		GenTime:      genTime.UTC(),
		Nonce:        nonce,
	}
	return asn1.Marshal(info)
}

// Timestamper выдаёт токен метки времени на значение подписи.
//
// Реализация обычно строит запрос через NewTimestampRequest, отправляет
// его службе по сети и возвращает токен из ответа. Сеть намеренно
// оставлена вызывающему коду: библиотека никуда сама не ходит.
type Timestamper func(signatureValue []byte) (token []byte, err error)

// SignatureValue возвращает значение подписи из SignerInfo. Именно оно
// подаётся службе штампов времени.
func (s *Signer) SignatureValue() []byte {
	return append([]byte(nil), s.info.Signature...)
}

// Timestamps возвращает метки времени из неподписанных атрибутов.
//
// Метки не проверяются: вызывающий код должен применить Verify к
// значению, которое возвращает SignatureValue.
func (s *Signer) Timestamps() ([]*Timestamp, error) {
	if len(s.info.UnsignedAttrs.FullBytes) == 0 {
		return nil, nil
	}
	attrs, err := parseAttributes(s.info.UnsignedAttrs)
	if err != nil {
		return nil, err
	}
	var out []*Timestamp
	for _, a := range attrs {
		if !a.Type.Equal(oidSignatureTimeStamp) {
			continue
		}
		elems, err := derElements(a.Values.Bytes)
		if err != nil {
			return nil, ErrMalformed
		}
		for _, e := range elems {
			ts, err := ParseTimestampToken(e)
			if err != nil {
				return nil, err
			}
			out = append(out, ts)
		}
	}
	return out, nil
}

// VerifyTimestamps проверяет все метки времени подписанта.
//
// Возвращает число проверенных меток. Отсутствие меток ошибкой не
// считается: их наличие требует профиль CAdES-T, а не сам CMS.
func (s *Signer) VerifyTimestamps() (int, error) {
	stamps, err := s.Timestamps()
	if err != nil {
		return 0, err
	}
	value := s.SignatureValue()
	for _, ts := range stamps {
		if err := ts.Verify(value); err != nil {
			return 0, err
		}
	}
	return len(stamps), nil
}

// marshalTimestampAttribute заворачивает токен в неподписанный атрибут.
func marshalTimestampAttribute(token []byte) ([]byte, error) {
	return asn1.Marshal(attribute{
		Type: oidSignatureTimeStamp,
		Values: asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: token,
		},
	})
}

// requestTimestamp вызывает службу и проверяет полученный токен: подпись
// с заведомо негодной меткой лучше не выпускать вовсе.
func requestTimestamp(ts Timestamper, signature []byte) ([]byte, error) {
	token, err := ts(signature)
	if err != nil {
		return nil, err
	}
	if len(token) == 0 {
		return nil, ErrNoTimestamp
	}
	parsed, err := ParseTimestampToken(token)
	if err != nil {
		return nil, err
	}
	if err := parsed.Verify(signature); err != nil {
		return nil, err
	}
	return token, nil
}
