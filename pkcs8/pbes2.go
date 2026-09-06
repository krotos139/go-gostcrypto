// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package pkcs8

import (
	"crypto/cipher"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/krotos139/go-gostcrypto/gost3410"
	"github.com/krotos139/go-gostcrypto/gostasn1"
	"github.com/krotos139/go-gostcrypto/kdf"
	"github.com/krotos139/go-gostcrypto/legacy/gost28147"
)

// Зашифрованный ключ: PBES2 по Р 50.1.111-2016.
//
// Ключ шифрования вырабатывается из пароля алгоритмом PBKDF2 на
// HMAC_GOSTR3411_2012_512, само шифрование — ГОСТ 28147-89 в режиме
// гаммирования с обратной связью и ключевым размешиванием CryptoPro.
//
// Пароль подаётся в кодировке UTF-8 без завершающего нуля (п. 5
// Р 50.1.112-2016).

var (
	// oidPBES2 — id-PBES2 (PKCS#5).
	oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	// oidPBKDF2 — id-PBKDF2 (PKCS#5).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	// oidHMAC512 — id-tc26-hmac-gost-3411-12-512, псевдослучайная
	// функция для PBKDF2.
	oidHMAC512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 2}
	// oidGost28147 — id-Gost28147-89, шифрование содержимого.
	oidGost28147 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}
)

var (
	// ErrPassword возвращается, если ключ не расшифровывается: пароль не
	// тот либо контейнер повреждён.
	ErrPassword = errors.New("pkcs8: ключ не расшифровывается указанным паролем")
	// ErrIterations возвращается при недопустимом числе итераций.
	ErrIterations = errors.New("pkcs8: недопустимое число итераций")
)

// DefaultIterations — число итераций PBKDF2 по умолчанию. Столько же
// использует контрольный пример Р 50.1.112-2016.
const DefaultIterations = 2000

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                 `asn1:"optional"`
	PRF            AlgorithmIdentifier `asn1:"optional"`
}

type gost28147Params struct {
	IV                 []byte
	EncryptionParamSet asn1.ObjectIdentifier
}

type pbes2Params struct {
	KeyDerivationFunc AlgorithmIdentifier
	EncryptionScheme  AlgorithmIdentifier
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm AlgorithmIdentifier
	EncryptedData       []byte
}

// deriveKey вырабатывает ключ шифрования из пароля.
func deriveKey(password, salt []byte, iterations int) []byte {
	return kdf.PBKDF2(password, salt, iterations, gost28147.KeySize)
}

// newStream создаёт поток для шифрования или расшифрования содержимого.
func newStream(key []byte, sbox *gost28147.SBox, iv []byte, decrypt bool) (cipher.Stream, error) {
	if decrypt {
		return gost28147.NewCFBDecrypterMeshed(key, sbox, iv)
	}
	return gost28147.NewCFBEncrypterMeshed(key, sbox, iv)
}

// ParseEncryptedPrivateKey расшифровывает и разбирает ключ из структуры
// EncryptedPrivateKeyInfo.
//
// Пароль передаётся в кодировке UTF-8 без завершающего нуля.
func ParseEncryptedPrivateKey(der, password []byte) (*gost3410.PrivateKey, error) {
	plain, err := DecryptPrivateKeyInfo(der, password)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(plain)
}

// DecryptPrivateKeyInfo расшифровывает EncryptedPrivateKeyInfo и
// возвращает вложенную структуру PrivateKeyInfo в кодировке DER.
//
// Нужна тем, кому кроме самого ключа важны его атрибуты.
func DecryptPrivateKeyInfo(der, password []byte) ([]byte, error) {
	var enc encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &enc); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if !enc.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, ErrUnsupported
	}

	return DecryptPBES2(enc.EncryptionAlgorithm, enc.EncryptedData, password)
}

// DecryptPBES2 расшифровывает данные по описанию алгоритма PBES2.
//
// Вынесена наружу потому, что тем же способом шифруются разделы
// транспортного ключевого контейнера, а не только сам ключ.
func DecryptPBES2(alg AlgorithmIdentifier, data, password []byte) ([]byte, error) {
	if !alg.Algorithm.Equal(oidPBES2) {
		return nil, ErrUnsupported
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil {
		return nil, ErrMalformed
	}
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, ErrUnsupported
	}
	if !params.EncryptionScheme.Algorithm.Equal(oidGost28147) {
		return nil, ErrUnsupported
	}

	var kp pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kp); err != nil {
		return nil, ErrMalformed
	}
	if kp.IterationCount <= 0 {
		return nil, ErrIterations
	}
	// Р 50.1.112-2016 задаёт единственную псевдослучайную функцию;
	// значение по умолчанию из PKCS#5 (HMAC-SHA-1) здесь неприменимо.
	if len(kp.PRF.Algorithm) != 0 && !kp.PRF.Algorithm.Equal(oidHMAC512) {
		return nil, ErrUnsupported
	}

	var cp gost28147Params
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &cp); err != nil {
		return nil, ErrMalformed
	}
	if len(cp.IV) != gost28147.BlockSize {
		return nil, ErrMalformed
	}
	sbox, err := gostasn1.SBoxByOID(cp.EncryptionParamSet)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, kp.Salt, kp.IterationCount)
	st, err := newStream(key, sbox, cp.IV, true)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	st.XORKeyStream(out, data)
	return out, nil
}

// EncryptOptions настраивает шифрование ключа.
type EncryptOptions struct {
	// Iterations — число итераций PBKDF2. Ноль означает
	// DefaultIterations.
	Iterations int
	// SaltSize — длина случайной соли в байтах, от 8 до 32
	// (п. 5 Р 50.1.112-2016). Ноль означает 32.
	SaltSize int
	// ParamSet — набор подстановок ГОСТ 28147-89. Нулевое значение
	// означает id-tc26-gost-28147-param-Z, как в контрольном примере.
	ParamSet asn1.ObjectIdentifier
	// Marshal настраивает кодирование самого ключа, в том числе
	// маскирование.
	Marshal *MarshalOptions
}

// MarshalEncryptedPrivateKey кодирует ключ и зашифровывает его на пароле.
func MarshalEncryptedPrivateKey(rnd io.Reader, priv *gost3410.PrivateKey, password []byte, opts *EncryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &EncryptOptions{}
	}
	iterations := opts.Iterations
	if iterations == 0 {
		iterations = DefaultIterations
	}
	if iterations < 0 {
		return nil, ErrIterations
	}
	saltSize := opts.SaltSize
	if saltSize == 0 {
		saltSize = 32
	}
	if saltSize < 8 || saltSize > 32 {
		return nil, ErrMalformed
	}
	paramSet := opts.ParamSet
	if paramSet == nil {
		paramSet = gostasn1.OIDCipherParamZ
	}
	sbox, err := gostasn1.SBoxByOID(paramSet)
	if err != nil {
		return nil, err
	}

	marshalOpts := opts.Marshal
	if marshalOpts == nil {
		marshalOpts = &MarshalOptions{Rand: rnd}
	} else if marshalOpts.Rand == nil {
		cp := *marshalOpts
		cp.Rand = rnd
		marshalOpts = &cp
	}
	plain, err := MarshalPrivateKey(priv, marshalOpts)
	if err != nil {
		return nil, err
	}

	alg, encrypted, err := encryptPBES2(rnd, plain, password, iterations, saltSize, paramSet, sbox)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: alg,
		EncryptedData:       encrypted,
	})
}

func encryptPBES2(rnd io.Reader, plain, password []byte, iterations, saltSize int, paramSet asn1.ObjectIdentifier, sbox *gost28147.SBox) (AlgorithmIdentifier, []byte, error) {
	var zero AlgorithmIdentifier

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return zero, nil, err
	}
	iv := make([]byte, gost28147.BlockSize)
	if _, err := io.ReadFull(rnd, iv); err != nil {
		return zero, nil, err
	}

	key := deriveKey(password, salt, iterations)
	st, err := newStream(key, sbox, iv, false)
	if err != nil {
		return zero, nil, err
	}
	encrypted := make([]byte, len(plain))
	st.XORKeyStream(encrypted, plain)

	kpDER, err := asn1.Marshal(pbkdf2Params{
		Salt:           salt,
		IterationCount: iterations,
		PRF:            AlgorithmIdentifier{Algorithm: oidHMAC512, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return zero, nil, err
	}
	cpDER, err := asn1.Marshal(gost28147Params{IV: iv, EncryptionParamSet: paramSet})
	if err != nil {
		return zero, nil, err
	}
	pbesDER, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: AlgorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kpDER},
		},
		EncryptionScheme: AlgorithmIdentifier{
			Algorithm:  oidGost28147,
			Parameters: asn1.RawValue{FullBytes: cpDER},
		},
	})
	if err != nil {
		return zero, nil, err
	}
	return AlgorithmIdentifier{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: pbesDER},
	}, encrypted, nil
}

// EncryptPBES2 зашифровывает произвольные данные на пароле и возвращает
// описание алгоритма вместе с шифртекстом.
//
// Нужна для шифрования разделов транспортного ключевого контейнера.
func EncryptPBES2(rnd io.Reader, plain, password []byte, opts *EncryptOptions) (AlgorithmIdentifier, []byte, error) {
	var zero AlgorithmIdentifier
	if opts == nil {
		opts = &EncryptOptions{}
	}
	iterations := opts.Iterations
	if iterations == 0 {
		iterations = DefaultIterations
	}
	if iterations < 0 {
		return zero, nil, ErrIterations
	}
	saltSize := opts.SaltSize
	if saltSize == 0 {
		saltSize = 32
	}
	if saltSize < 8 || saltSize > 32 {
		return zero, nil, ErrMalformed
	}
	paramSet := opts.ParamSet
	if paramSet == nil {
		paramSet = gostasn1.OIDCipherParamZ
	}
	sbox, err := gostasn1.SBoxByOID(paramSet)
	if err != nil {
		return zero, nil, err
	}
	return encryptPBES2(rnd, plain, password, iterations, saltSize, paramSet, sbox)
}
