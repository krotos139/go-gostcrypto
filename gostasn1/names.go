// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gostasn1

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
)

// Отечественные дополнения к отличительному имени и расширения
// квалифицированных сертификатов (RFC 9215, раздел 5).
//
// crypto/x509 этих идентификаторов не знает и выводит их числами вроде
// «1.2.643.100.4=#130A37373037333239313532», из-за чего имя владельца
// сертификата читается плохо. Здесь они получают имена и удобный доступ.

var (
	// OIDOGRN — основной государственный регистрационный номер
	// юридического лица.
	OIDOGRN = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
	// OIDSNILS — страховой номер индивидуального лицевого счёта.
	OIDSNILS = asn1.ObjectIdentifier{1, 2, 643, 100, 3}
	// OIDINNLE — ИНН юридического лица.
	OIDINNLE = asn1.ObjectIdentifier{1, 2, 643, 100, 4}
	// OIDOGRNIP — ОГРН индивидуального предпринимателя.
	OIDOGRNIP = asn1.ObjectIdentifier{1, 2, 643, 100, 5}
	// OIDIdentificationKind — способ, которым удостоверяющий центр
	// установил личность получателя сертификата.
	OIDIdentificationKind = asn1.ObjectIdentifier{1, 2, 643, 100, 114}
	// OIDINN — ИНН физического лица. В RFC 9215 отнесён к
	// унаследованным (раздел 6), но встречается повсеместно.
	OIDINN = asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1}

	// OIDSubjectSignTool — средство электронной подписи владельца.
	OIDSubjectSignTool = asn1.ObjectIdentifier{1, 2, 643, 100, 111}
	// OIDIssuerSignTool — средства удостоверяющего центра.
	OIDIssuerSignTool = asn1.ObjectIdentifier{1, 2, 643, 100, 112}
)

// AttributeName возвращает принятое сокращение для идентификатора
// атрибута имени: OGRN, SNILS, INN и так далее.
//
// Для неизвестных идентификаторов возвращается пустая строка.
func AttributeName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDOGRN):
		return "OGRN"
	case oid.Equal(OIDSNILS):
		return "SNILS"
	case oid.Equal(OIDINNLE):
		return "INNLE"
	case oid.Equal(OIDOGRNIP):
		return "OGRNIP"
	case oid.Equal(OIDINN):
		return "INN"
	case oid.Equal(OIDIdentificationKind):
		return "IdentificationKind"
	}
	return ""
}

// Attributes собирает отечественные атрибуты отличительного имени.
//
// Ключ — сокращение из AttributeName, значение — содержимое атрибута.
// Обычные атрибуты (CN, O, C и прочие) сюда не попадают: их разбирает
// crypto/x509.
func Attributes(name pkix.Name) map[string]string {
	out := make(map[string]string)
	for _, a := range name.Names {
		key := AttributeName(a.Type)
		if key == "" {
			continue
		}
		if s, ok := a.Value.(string); ok {
			out[key] = s
		}
	}
	return out
}

// shortNames — принятые сокращения для распространённых атрибутов
// имени. Отечественные добавлены к обычным из X.520.
var shortNames = map[string]string{
	"2.5.4.3":              "CN",
	"2.5.4.4":              "SN",
	"2.5.4.42":             "GN",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "ST",
	"2.5.4.9":              "STREET",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"2.5.4.12":             "T",
	"2.5.4.5":              "SERIALNUMBER",
	"1.2.840.113549.1.9.1": "E",
	"1.2.643.100.1":        "OGRN",
	"1.2.643.100.3":        "SNILS",
	"1.2.643.100.4":        "INNLE",
	"1.2.643.100.5":        "OGRNIP",
	"1.2.643.100.114":      "IdentificationKind",
	"1.2.643.3.131.1.1":    "INN",
}

// FormatName выводит отличительное имя в читаемом виде.
//
// Отличие от pkix.Name.String в том, что неизвестные ему отечественные
// атрибуты выводятся не числовым идентификатором с шестнадцатеричным
// значением, а сокращением и самим значением.
func FormatName(name pkix.Name) string {
	var parts []string
	// Порядок принят от частного к общему, как в X.500: сначала имя,
	// в конце страна.
	for i := len(name.Names) - 1; i >= 0; i-- {
		a := name.Names[i]
		key := shortNames[a.Type.String()]
		if key == "" {
			key = a.Type.String()
		}
		value, ok := a.Value.(string)
		if !ok {
			continue
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ", ")
}

// SignTool — сведения о средстве электронной подписи из расширений
// сертификата (RFC 9215, пп. 5.3 и 5.4).
type SignTool struct {
	// Subject — средство подписи владельца сертификата.
	Subject string
	// Issuer — средства удостоверяющего центра. Расширение хранит
	// четыре строки: средство подписи центра, средство удостоверяющего
	// центра и два номера заключений о соответствии.
	Issuer []string
}

// SignTools извлекает сведения о средствах подписи из расширений
// сертификата.
//
// Значения носят справочный характер: они заявлены удостоверяющим
// центром и проверке не подлежат.
func SignTools(cert *x509.Certificate) SignTool {
	var st SignTool
	for _, e := range cert.Extensions {
		switch {
		case e.Id.Equal(OIDSubjectSignTool):
			var s string
			if _, err := asn1.Unmarshal(e.Value, &s); err == nil {
				st.Subject = s
			}
		case e.Id.Equal(OIDIssuerSignTool):
			// IssuerSignTool ::= SEQUENCE из четырёх строк.
			var seq struct {
				SignTool     string `asn1:"utf8,optional"`
				CATool       string `asn1:"utf8,optional"`
				SignToolCert string `asn1:"utf8,optional"`
				CAToolCert   string `asn1:"utf8,optional"`
			}
			if _, err := asn1.Unmarshal(e.Value, &seq); err == nil {
				st.Issuer = []string{seq.SignTool, seq.CATool, seq.SignToolCert, seq.CAToolCert}
			}
		}
	}
	return st
}
