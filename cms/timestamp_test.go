// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package cms

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
)

// Реальной службы штампов времени под рукой нет, поэтому её роль играет
// сама библиотека: она выпускает токен по RFC 3161 и она же его
// проверяет. Такой опыт проверяет разбор и сборку структур, но, конечно,
// не совместимость с чужими службами — для этого нужен настоящий ответ.

var tsaPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// testTSA — служба штампов времени на той же библиотеке.
type testTSA struct {
	priv   *gost3410.PrivateKey
	cert   *x509.Certificate
	serial int64
	// genTime фиксировано, чтобы тесты не зависели от часов.
	genTime time.Time
}

func newTestTSA(t testing.TB, c *gost3410.Curve) *testTSA {
	t.Helper()
	priv, cert := newSignerPair(t, c, "служба штампов времени", 1000)
	return &testTSA{
		priv:    priv,
		cert:    cert,
		genTime: time.Date(2026, 9, 6, 15, 30, 0, 0, time.UTC),
	}
}

// issue выпускает токен на произвольные данные.
func (s *testTSA) issue(t testing.TB, data []byte) []byte {
	t.Helper()
	digestOID := gostasn1.OIDDigest256
	if s.priv.Curve.Size() > 32 {
		digestOID = gostasn1.OIDDigest512
	}
	d := gostasn1.DigestForCurve(s.priv.Curve, data)

	s.serial++
	info, err := MarshalTSTInfo(d, digestOID, tsaPolicy, big.NewInt(s.serial), s.genTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Токен — подписанное сообщение со встроенной TSTInfo.
	token, err := Sign(rand.Reader, info, s.cert, s.priv, &SignOptions{
		ContentType: OIDContentTypeTSTInfo,
		SigningTime: s.genTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (s *testTSA) timestamper(t testing.TB) Timestamper {
	return func(signature []byte) ([]byte, error) {
		return s.issue(t, signature), nil
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	content := []byte("документ с меткой времени")

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, cert := newSignerPair(t, tc.curve, "подписант", 1)
			tsa := newTestTSA(t, tc.curve)

			der, err := Sign(rand.Reader, content, cert, priv, &SignOptions{
				Detached:  true,
				Timestamp: tsa.timestamper(t),
			})
			if err != nil {
				t.Fatal(err)
			}

			sd, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := sd.Verify(content); err != nil {
				t.Fatalf("подпись не прошла: %v", err)
			}

			n, err := sd.Signers[0].VerifyTimestamps()
			if err != nil {
				t.Fatalf("метка времени не прошла: %v", err)
			}
			if n != 1 {
				t.Fatalf("меток времени: %d, ожидалась одна", n)
			}

			stamps, err := sd.Signers[0].Timestamps()
			if err != nil {
				t.Fatal(err)
			}
			if !stamps[0].GenTime.Equal(tsa.genTime) {
				t.Errorf("время метки = %v, ожидалось %v", stamps[0].GenTime, tsa.genTime)
			}
			if !stamps[0].Policy.Equal(tsaPolicy) {
				t.Errorf("политика = %v", stamps[0].Policy)
			}
		})
	}
}

// Метка выдана на значение подписи: к другой подписи она не подойдёт.
// Это и есть то, ради чего она нужна.
func TestTimestampBoundToSignature(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "подписант", 2)
	tsa := newTestTSA(t, c)

	der, err := Sign(rand.Reader, []byte("первый документ"), cert, priv, &SignOptions{
		Detached:  true,
		Timestamp: tsa.timestamper(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	stamps, err := sd.Signers[0].Timestamps()
	if err != nil {
		t.Fatal(err)
	}

	// Своя подпись — метка сходится.
	if err := stamps[0].Verify(sd.Signers[0].SignatureValue()); err != nil {
		t.Fatalf("своя подпись: %v", err)
	}

	// Чужая подпись — не должна.
	other, err := Sign(rand.Reader, []byte("второй документ"), cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sdOther, err := Parse(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := stamps[0].Verify(sdOther.Signers[0].SignatureValue()); err != ErrTimestampImprint {
		t.Errorf("чужая подпись: err = %v", err)
	}

	// Изменение одного байта значения подписи тоже ломает метку.
	bad := sd.Signers[0].SignatureValue()
	bad[0] ^= 0x01
	if err := stamps[0].Verify(bad); err != ErrTimestampImprint {
		t.Errorf("изменённое значение подписи: err = %v", err)
	}
}

// Испорченная подпись службы обязана отвергаться.
func TestTimestampRejectsTamperedToken(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "подписант", 3)
	tsa := newTestTSA(t, c)

	sig, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(sig)
	if err != nil {
		t.Fatal(err)
	}
	value := sd.Signers[0].SignatureValue()

	token := tsa.issue(t, value)
	ts, err := ParseTimestampToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Verify(value); err != nil {
		t.Fatalf("целый токен: %v", err)
	}

	// Портим подпись службы внутри токена.
	bad := append([]byte(nil), token...)
	for i := len(bad) - 1; i >= 0; i-- {
		if bad[i] != 0 {
			bad[i] ^= 0x01
			break
		}
	}
	if ts2, err := ParseTimestampToken(bad); err == nil {
		if err := ts2.Verify(value); err == nil {
			t.Error("испорченный токен прошёл проверку")
		}
	}
}

// Токен, выданный не на ту подпись, не должен попадать в готовое
// сообщение: Sign обязана его отвергнуть.
func TestSignRejectsBadTimestamp(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "подписант", 4)
	tsa := newTestTSA(t, c)

	// Служба, выдающая метку на посторонние данные.
	wrong := func(signature []byte) ([]byte, error) {
		return tsa.issue(t, []byte("совсем другие данные")), nil
	}
	if _, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{
		Detached:  true,
		Timestamp: wrong,
	}); err != ErrTimestampImprint {
		t.Errorf("негодная метка: err = %v", err)
	}

	// Служба, вернувшая мусор.
	junk := func(signature []byte) ([]byte, error) { return []byte{0x30, 0x00}, nil }
	if _, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{
		Detached:  true,
		Timestamp: junk,
	}); err == nil {
		t.Error("мусор вместо токена принят")
	}

	// Служба, вернувшая пустоту.
	empty := func(signature []byte) ([]byte, error) { return nil, nil }
	if _, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{
		Detached:  true,
		Timestamp: empty,
	}); err != ErrNoTimestamp {
		t.Errorf("пустой токен: err = %v", err)
	}
}

// Токен подписанного сообщения с чужим типом содержимого меткой не
// является.
func TestParseTimestampTokenRejectsPlainSignature(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "обычная подпись", 5)
	der, err := Sign(rand.Reader, []byte("обычный документ"), cert, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTimestampToken(der); err != ErrUnsupported {
		t.Errorf("обычная подпись принята как метка: err = %v", err)
	}
	if _, err := ParseTimestampToken(nil); err != ErrMalformed {
		t.Errorf("пустой вход: err = %v", err)
	}
}

func TestTimestampRequest(t *testing.T) {
	d := make([]byte, 32)
	for i := range d {
		d[i] = byte(i)
	}
	nonce := big.NewInt(0x0123456789ABCDEF)

	req, err := NewTimestampRequest(d, gostasn1.OIDDigest256, &TimestampRequestOptions{
		Policy:             tsaPolicy,
		Nonce:              nonce,
		RequestCertificate: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	var parsed timeStampReq
	if rest, err := asn1.Unmarshal(req, &parsed); err != nil || len(rest) != 0 {
		t.Fatalf("запрос не разбирается: %v", err)
	}
	if parsed.Version != 1 {
		t.Errorf("версия = %d", parsed.Version)
	}
	if !bytes.Equal(parsed.MessageImprint.HashedMessage, d) {
		t.Error("хэш в запросе не совпал")
	}
	if !parsed.MessageImprint.HashAlgorithm.Algorithm.Equal(gostasn1.OIDDigest256) {
		t.Error("алгоритм хэширования в запросе не тот")
	}
	if parsed.Nonce == nil || parsed.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce = %v", parsed.Nonce)
	}
	if !parsed.CertReq {
		t.Error("запрос сертификата не выставлен")
	}

	if _, err := NewTimestampRequest(nil, gostasn1.OIDDigest256, nil); err != ErrMalformed {
		t.Error("пустой хэш принят")
	}
}

// Ответ службы разбирается; отказ отличается от выдачи.
// makeResponse собирает TimeStampResp вручную: PKIStatusInfo - это
// SEQUENCE, у которой обязателен только первый элемент.
func makeResponse(t testing.TB, status int, token []byte) ([]byte, error) {
	t.Helper()
	statusDER, err := asn1.Marshal(status)
	if err != nil {
		return nil, err
	}
	body := derWrap(0x30, statusDER)
	body = append(body, token...)
	return derWrap(0x30, body), nil
}

func TestTimestampResponse(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	tsa := newTestTSA(t, c)
	data := []byte("данные для метки")
	token := tsa.issue(t, data)

	// Успешный ответ.
	resp, err := makeResponse(t, 0, token)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := ParseTimestampResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Verify(data); err != nil {
		t.Fatalf("метка из ответа не прошла: %v", err)
	}
	if !bytes.Equal(ts.Raw(), token) {
		t.Error("Raw вернул не тот токен")
	}

	// Отказ службы.
	for _, status := range []int{2, 3, 5} {
		bad, err := makeResponse(t, status, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseTimestampResponse(bad); err != ErrTimestampStatus {
			t.Errorf("статус %d: err = %v", status, err)
		}
	}

	// Успешный статус без токена.
	empty, err := makeResponse(t, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTimestampResponse(empty); err != ErrMalformed {
		t.Error("ответ без токена принят")
	}
}

// Без метки VerifyTimestamps не считается ошибкой: её требует профиль
// CAdES-T, а не сам CMS.
func TestNoTimestampIsNotAnError(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "без метки", 6)
	der, err := Sign(rand.Reader, []byte("x"), cert, priv, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	n, err := sd.Signers[0].VerifyTimestamps()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("меток: %d, ожидалось ноль", n)
	}
}

// Метка лежит в неподписанных атрибутах и подписью не покрыта: её
// удаление не должно ломать саму подпись. Это не изъян, а устройство
// формата — метка появляется после того, как подпись вычислена.
func TestTimestampIsUnsigned(t *testing.T) {
	c := gost3410.TC26ParamSet256A()
	priv, cert := newSignerPair(t, c, "подписант", 7)
	tsa := newTestTSA(t, c)
	content := []byte("документ")

	withTS, err := Sign(rand.Reader, content, cert, priv, &SignOptions{
		Detached:  true,
		Timestamp: tsa.timestamper(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := Parse(withTS)
	if err != nil {
		t.Fatal(err)
	}
	if len(sd.Signers[0].info.UnsignedAttrs.FullBytes) == 0 {
		t.Fatal("неподписанные атрибуты пусты")
	}
	if err := sd.Verify(content); err != nil {
		t.Fatal(err)
	}
	if n, _ := sd.Signers[0].VerifyTimestamps(); n != 1 {
		t.Fatalf("меток: %d", n)
	}
}
