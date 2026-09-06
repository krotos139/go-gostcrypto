// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/krotos139/go-gostcrypto/gost3412/kuznyechik"
	"github.com/krotos139/go-gostcrypto/gost3412/magma"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("некорректный hex %q: %v", s, err)
	}
	return b
}

// vectors — контрольные примеры из приложения А ГОСТ Р 34.13-2015.
// А.1 — для "Кузнечика" (n = 128 бит), А.2 — для "Магмы" (n = 64 бита).
type vectors struct {
	name    string
	newCiph func(key []byte) (cipher.Block, error)
	key     string
	plain   string

	ecb string

	ctrIV string
	ctr   string

	ofbIV string
	ofb   string

	cbcIV string
	cbc   string

	cfbIV string
	cfb   string

	macR, macK1, macK2 string
	macSize            int
	mac                string
}

var kuznyechikVectors = vectors{
	name:    "кузнечик",
	newCiph: kuznyechik.NewCipher,
	key:     "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
	plain: "1122334455667700ffeeddccbbaa9988" +
		"00112233445566778899aabbcceeff0a" +
		"112233445566778899aabbcceeff0a00" +
		"2233445566778899aabbcceeff0a0011",

	ecb: "7f679d90bebc24305a468d42b9d4edcd" +
		"b429912c6e0032f9285452d76718d08b" +
		"f0ca33549d247ceef3f5a5313bd4b157" +
		"d0b09ccde830b9eb3a02c4c5aa8ada98",

	ctrIV: "1234567890abcef0",
	ctr: "f195d8bec10ed1dbd57b5fa240bda1b8" +
		"85eee733f6a13e5df33ce4b33c45dee4" +
		"a5eae88be6356ed3d5e877f13564a3a5" +
		"cb91fab1f20cbab6d1c6d15820bdba73",

	ofbIV: "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819",
	ofb: "81800a59b1842b24ff1f795e897abd95" +
		"ed5b47a7048cfab48fb521369d9326bf" +
		"66a257ac3ca0b8b1c80fe7fc10288a13" +
		"203ebbc066138660a0292243f6903150",

	cbcIV: "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819",
	cbc: "689972d4a085fa4d90e52e3d6d7dcc27" +
		"2826e661b478eca6af1e8e448d5ea5ac" +
		"fe7babf1e91999e85640e8b0f49d90d0" +
		"167688065a895c631a2d9a1560b63970",

	cfbIV: "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819",
	cfb: "81800a59b1842b24ff1f795e897abd95" +
		"ed5b47a7048cfab48fb521369d9326bf" +
		"79f2a8eb5cc68d38842d264e97a238b5" +
		"4ffebecd4e922de6c75bd9dd44fbf4d1",

	macR:    "94bec15e269cf1e506f02b994c0a8ea0",
	macK1:   "297d82bc4d39e3ca0de0573298151dc7",
	macK2:   "52fb05789a73c7941bc0ae65302a3b8e",
	macSize: 8, // s = 64 бита
	mac:     "336f4d296059fbe3",
}

var magmaVectors = vectors{
	name:    "магма",
	newCiph: magma.NewCipher,
	key:     "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	plain: "92def06b3c130a59" +
		"db54c704f8189d20" +
		"4a98fb2e67a8024c" +
		"8912409b17b57e41",

	ecb: "2b073f0494f372a0" +
		"de70e715d3556e48" +
		"11d8d9e9eacfbc1e" +
		"7c68260996c67efb",

	ctrIV: "12345678",
	ctr: "4e98110c97b7b93c" +
		"3e250d93d6e85d69" +
		"136d868807b2dbef" +
		"568eb680ab52a12d",

	ofbIV: "1234567890abcdef234567890abcdef1",
	ofb: "db37e0e266903c83" +
		"0d46644c1f9a089c" +
		"a0f83062430e327e" +
		"c824efb8bd4fdb05",

	cbcIV: "1234567890abcdef234567890abcdef134567890abcdef12",
	cbc: "96d1b05eea683919" +
		"aff76129abb937b9" +
		"5058b4a1c4bc0019" +
		"20b78b1a7cd7e667",

	cfbIV: "1234567890abcdef234567890abcdef1",
	cfb: "db37e0e266903c83" +
		"0d46644c1f9a089c" +
		"24bdd2035315d38b" +
		"bcc0321421075505",

	macR:    "2fa2cd99a1290a12",
	macK1:   "5f459b3342521424",
	macK2:   "be8b366684a42848",
	macSize: 4, // s = 32 бита
	mac:     "154e7210",
}

var allVectors = []vectors{kuznyechikVectors, magmaVectors}

func (v vectors) block(t testing.TB) cipher.Block {
	t.Helper()
	b, err := v.newCiph(mustHex(t, v.key))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- режимы ---------------------------------------------------------------

// ГОСТ Р 34.13-2015, приложения А.1.1 и А.2.1.
func TestECB(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)
			plain, want := mustHex(t, v.plain), mustHex(t, v.ecb)

			got := make([]byte, len(plain))
			NewECBEncrypter(b).CryptBlocks(got, plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("зашифрование = %x, ожидалось %x", got, want)
			}

			back := make([]byte, len(want))
			NewECBDecrypter(b).CryptBlocks(back, want)
			if !bytes.Equal(back, plain) {
				t.Fatalf("расшифрование = %x, ожидалось %x", back, plain)
			}
		})
	}
}

// ГОСТ Р 34.13-2015, приложения А.1.2 и А.2.2.
func TestCTR(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			plain, want := mustHex(t, v.plain), mustHex(t, v.ctr)

			s, err := NewCTR(v.block(t), mustHex(t, v.ctrIV))
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			s.XORKeyStream(got, plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("зашифрование = %x, ожидалось %x", got, want)
			}

			// Гаммирование симметрично: тот же поток восстанавливает текст.
			s, err = NewCTR(v.block(t), mustHex(t, v.ctrIV))
			if err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(want))
			s.XORKeyStream(back, want)
			if !bytes.Equal(back, plain) {
				t.Fatalf("расшифрование = %x, ожидалось %x", back, plain)
			}
		})
	}
}

// ГОСТ Р 34.13-2015, приложения А.1.3 и А.2.3.
func TestOFB(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			plain, want := mustHex(t, v.plain), mustHex(t, v.ofb)

			s, err := NewOFB(v.block(t), mustHex(t, v.ofbIV))
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			s.XORKeyStream(got, plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("зашифрование = %x, ожидалось %x", got, want)
			}

			s, err = NewOFB(v.block(t), mustHex(t, v.ofbIV))
			if err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(want))
			s.XORKeyStream(back, want)
			if !bytes.Equal(back, plain) {
				t.Fatalf("расшифрование = %x, ожидалось %x", back, plain)
			}
		})
	}
}

// ГОСТ Р 34.13-2015, приложения А.1.4 и А.2.4.
// Для "Магмы" здесь m = 3n — намеренно, чтобы проверить многоблочный регистр.
func TestCBC(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			plain, want := mustHex(t, v.plain), mustHex(t, v.cbc)

			enc, err := NewCBCEncrypter(v.block(t), mustHex(t, v.cbcIV))
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			enc.CryptBlocks(got, plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("зашифрование = %x, ожидалось %x", got, want)
			}

			dec, err := NewCBCDecrypter(v.block(t), mustHex(t, v.cbcIV))
			if err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(want))
			dec.CryptBlocks(back, want)
			if !bytes.Equal(back, plain) {
				t.Fatalf("расшифрование = %x, ожидалось %x", back, plain)
			}
		})
	}
}

// ГОСТ Р 34.13-2015, приложения А.1.5 и А.2.5.
func TestCFB(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			plain, want := mustHex(t, v.plain), mustHex(t, v.cfb)

			enc, err := NewCFBEncrypter(v.block(t), mustHex(t, v.cfbIV))
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			enc.XORKeyStream(got, plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("зашифрование = %x, ожидалось %x", got, want)
			}

			dec, err := NewCFBDecrypter(v.block(t), mustHex(t, v.cfbIV))
			if err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(want))
			dec.XORKeyStream(back, want)
			if !bytes.Equal(back, plain) {
				t.Fatalf("расшифрование = %x, ожидалось %x", back, plain)
			}
		})
	}
}

// ГОСТ Р 34.13-2015, приложения А.1.6 и А.2.6.
func TestMAC(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)

			r, k1, k2, err := deriveSubkeys(b)
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, v.macR); !bytes.Equal(r, want) {
				t.Errorf("R = %x, ожидалось %x", r, want)
			}
			if want := mustHex(t, v.macK1); !bytes.Equal(k1, want) {
				t.Errorf("K1 = %x, ожидалось %x", k1, want)
			}
			if want := mustHex(t, v.macK2); !bytes.Equal(k2, want) {
				t.Errorf("K2 = %x, ожидалось %x", k2, want)
			}

			m, err := NewMAC(b, v.macSize)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Write(mustHex(t, v.plain)); err != nil {
				t.Fatal(err)
			}
			got := m.Sum(nil)
			if want := mustHex(t, v.mac); !bytes.Equal(got, want) {
				t.Fatalf("MAC = %x, ожидалось %x", got, want)
			}

			// Sum не должен менять состояние: повторный вызов даёт то же.
			if again := m.Sum(nil); !bytes.Equal(again, got) {
				t.Fatalf("повторный Sum = %x, ожидалось %x", again, got)
			}

			// После Reset и повторной записи результат должен совпасть.
			m.Reset()
			if _, err := m.Write(mustHex(t, v.plain)); err != nil {
				t.Fatal(err)
			}
			if after := m.Sum(nil); !bytes.Equal(after, got) {
				t.Fatalf("после Reset MAC = %x, ожидалось %x", after, got)
			}
		})
	}
}

// Побайтовая и рваная запись должны давать тот же результат, что и один
// вызов: имитовставка обязана обрабатывать последний блок особым образом
// независимо от того, как данные нарезаны на Write.
func TestMACChunked(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			plain := mustHex(t, v.plain)
			want := mustHex(t, v.mac)

			for _, chunk := range []int{1, 3, 5, 7, 8, 15, 16, 17, 31, 64} {
				m, err := NewMAC(v.block(t), v.macSize)
				if err != nil {
					t.Fatal(err)
				}
				for off := 0; off < len(plain); off += chunk {
					end := min(off+chunk, len(plain))
					if _, err := m.Write(plain[off:end]); err != nil {
						t.Fatal(err)
					}
				}
				if got := m.Sum(nil); !bytes.Equal(got, want) {
					t.Errorf("кусками по %d: MAC = %x, ожидалось %x", chunk, got, want)
				}
			}
		})
	}
}

// Пустое сообщение: последний блок неполон, поэтому применяется процедура
// дополнения 2 и вспомогательный ключ K2.
func TestMACEmpty(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)
			m, err := NewMAC(b, v.macSize)
			if err != nil {
				t.Fatal(err)
			}
			got := m.Sum(nil)

			// Проверка по определению: MAC = T_s(e_K(0x80||0... xor K2)).
			_, _, k2, err := deriveSubkeys(b)
			if err != nil {
				t.Fatal(err)
			}
			bs := b.BlockSize()
			buf := make([]byte, bs)
			buf[0] = 0x80
			xorBytes(buf, buf, k2, bs)
			b.Encrypt(buf, buf)
			if want := buf[:v.macSize]; !bytes.Equal(got, want) {
				t.Fatalf("MAC пустого сообщения = %x, ожидалось %x", got, want)
			}
		})
	}
}

// --- потоковая нарезка ----------------------------------------------------

// Режимы гаммирования обязаны давать одинаковый результат независимо от
// того, как данные нарезаны между вызовами XORKeyStream. Для CFB это
// особенно важно: регистр обратной связи обновляется только по завершении
// блока в s байт.
func TestStreamChunked(t *testing.T) {
	type ctor struct {
		name string
		make func(v vectors, t *testing.T) (cipher.Stream, []byte)
	}
	ctors := []ctor{
		{"ctr", func(v vectors, t *testing.T) (cipher.Stream, []byte) {
			s, err := NewCTR(v.block(t), mustHex(t, v.ctrIV))
			if err != nil {
				t.Fatal(err)
			}
			return s, mustHex(t, v.ctr)
		}},
		{"ofb", func(v vectors, t *testing.T) (cipher.Stream, []byte) {
			s, err := NewOFB(v.block(t), mustHex(t, v.ofbIV))
			if err != nil {
				t.Fatal(err)
			}
			return s, mustHex(t, v.ofb)
		}},
		{"cfb", func(v vectors, t *testing.T) (cipher.Stream, []byte) {
			s, err := NewCFBEncrypter(v.block(t), mustHex(t, v.cfbIV))
			if err != nil {
				t.Fatal(err)
			}
			return s, mustHex(t, v.cfb)
		}},
	}

	for _, v := range allVectors {
		for _, c := range ctors {
			t.Run(v.name+"/"+c.name, func(t *testing.T) {
				plain := mustHex(t, v.plain)
				for _, chunk := range []int{1, 3, 5, 7, 8, 13, 16, 17, 33} {
					s, want := c.make(v, t)
					got := make([]byte, len(plain))
					for off := 0; off < len(plain); off += chunk {
						end := min(off+chunk, len(plain))
						s.XORKeyStream(got[off:end], plain[off:end])
					}
					if !bytes.Equal(got, want) {
						t.Errorf("кусками по %d: %x, ожидалось %x", chunk, got, want)
					}
				}
			})
		}
	}
}

// Шифрование "на месте": dst и src совпадают.
func TestStreamInPlace(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			buf := mustHex(t, v.plain)
			s, err := NewCFBEncrypter(v.block(t), mustHex(t, v.cfbIV))
			if err != nil {
				t.Fatal(err)
			}
			s.XORKeyStream(buf, buf)
			if want := mustHex(t, v.cfb); !bytes.Equal(buf, want) {
				t.Fatalf("CFB на месте = %x, ожидалось %x", buf, want)
			}
		})
	}
}

// Неполный последний блок: стандарт усекает гамму до длины остатка
// (T_r в формулах), поэтому шифртекст должен совпадать с префиксом
// полноблочного результата.
func TestPartialTail(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			full := mustHex(t, v.plain)
			for _, n := range []int{1, 5, 9, 20, 33} {
				if n > len(full) {
					continue
				}
				s, err := NewCTR(v.block(t), mustHex(t, v.ctrIV))
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, n)
				s.XORKeyStream(got, full[:n])
				if want := mustHex(t, v.ctr)[:n]; !bytes.Equal(got, want) {
					t.Errorf("хвост %d байт: %x, ожидалось %x", n, got, want)
				}
			}
		})
	}
}

// --- совместимость со стандартной библиотекой -----------------------------

// При z = 1 режим простой замены с зацеплением обязан совпасть с
// классическим CBC из crypto/cipher.
func TestCBCMatchesStdlib(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)
			bs := b.BlockSize()
			iv := mustHex(t, v.cbcIV)[:bs] // z = 1
			plain := mustHex(t, v.plain)

			ours, err := NewCBCEncrypter(b, iv)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			ours.CryptBlocks(got, plain)

			want := make([]byte, len(plain))
			cipher.NewCBCEncrypter(v.block(t), iv).CryptBlocks(want, plain)

			if !bytes.Equal(got, want) {
				t.Fatalf("CBC(z=1) = %x, crypto/cipher даёт %x", got, want)
			}
		})
	}
}

// При s = n режим гаммирования обязан совпасть с CTR из crypto/cipher,
// если тому подать синхропосылку, дополненную нулями до целого блока.
func TestCTRMatchesStdlib(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)
			bs := b.BlockSize()
			iv := mustHex(t, v.ctrIV)
			plain := mustHex(t, v.plain)

			ours, err := NewCTR(b, iv)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			ours.XORKeyStream(got, plain)

			stdIV := make([]byte, bs)
			copy(stdIV, iv)
			want := make([]byte, len(plain))
			cipher.NewCTR(v.block(t), stdIV).XORKeyStream(want, plain)

			if !bytes.Equal(got, want) {
				t.Fatalf("CTR(s=n) = %x, crypto/cipher даёт %x", got, want)
			}
		})
	}
}

// --- параметры и ошибки ---------------------------------------------------

func TestParamValidation(t *testing.T) {
	b, err := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	bs := b.BlockSize()

	t.Run("ctr/длина iv", func(t *testing.T) {
		for _, n := range []int{0, 1, bs/2 - 1, bs/2 + 1, bs} {
			if _, err := NewCTR(b, make([]byte, n)); err != ErrIVSize {
				t.Errorf("iv длины %d: err = %v, ожидалось ErrIVSize", n, err)
			}
		}
	})
	t.Run("ctr/параметр s", func(t *testing.T) {
		for _, s := range []int{-1, 0, bs + 1} {
			if _, err := NewCTRWithS(b, make([]byte, bs/2), s); err != ErrSParam {
				t.Errorf("s = %d: err = %v, ожидалось ErrSParam", s, err)
			}
		}
	})
	t.Run("ofb/длина iv", func(t *testing.T) {
		for _, n := range []int{0, 1, bs - 1, bs + 1, 2*bs - 1} {
			if _, err := NewOFB(b, make([]byte, n)); err != ErrIVSize {
				t.Errorf("iv длины %d: err = %v, ожидалось ErrIVSize", n, err)
			}
		}
	})
	t.Run("cbc/длина iv", func(t *testing.T) {
		for _, n := range []int{0, 1, bs - 1, bs + 1} {
			if _, err := NewCBCEncrypter(b, make([]byte, n)); err != ErrIVSize {
				t.Errorf("iv длины %d: err = %v, ожидалось ErrIVSize", n, err)
			}
		}
	})
	t.Run("cfb/длина iv", func(t *testing.T) {
		for _, n := range []int{0, 1, bs - 1} {
			if _, err := NewCFBEncrypter(b, make([]byte, n)); err != ErrIVSize {
				t.Errorf("iv длины %d: err = %v, ожидалось ErrIVSize", n, err)
			}
		}
	})
	t.Run("mac/длина имитовставки", func(t *testing.T) {
		for _, n := range []int{-1, 0, bs + 1} {
			if _, err := NewMAC(b, n); err != ErrTagSize {
				t.Errorf("tagSize = %d: err = %v, ожидалось ErrTagSize", n, err)
			}
		}
	})
}

// --- дополнение -----------------------------------------------------------

func TestPad1(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"11", "1100000000000000"},
		{"1122334455667788", "1122334455667788"},
		{"112233445566778899", "1122334455667788" + "9900000000000000"},
	}
	for _, c := range cases {
		got := Pad1(mustHex(t, c.in), 8)
		if want := mustHex(t, c.want); !bytes.Equal(got, want) {
			t.Errorf("Pad1(%s) = %x, ожидалось %s", c.in, got, c.want)
		}
	}
}

func TestPad2(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "8000000000000000"},
		{"11", "1180000000000000"},
		{"1122334455667788", "1122334455667788" + "8000000000000000"},
		{"112233445566778899", "1122334455667788" + "9980000000000000"},
	}
	for _, c := range cases {
		got := Pad2(mustHex(t, c.in), 8)
		if want := mustHex(t, c.want); !bytes.Equal(got, want) {
			t.Errorf("Pad2(%s) = %x, ожидалось %s", c.in, got, c.want)
		}
		back, err := Unpad2(got)
		if err != nil {
			t.Errorf("Unpad2(%x): %v", got, err)
			continue
		}
		if want := mustHex(t, c.in); !bytes.Equal(back, want) {
			t.Errorf("Unpad2(Pad2(%s)) = %x", c.in, back)
		}
	}
}

func TestPad3(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "8000000000000000"}, // пустое сообщение считается неполным блоком
		{"11", "1180000000000000"},
		{"1122334455667788", "1122334455667788"}, // полный блок не дополняется
		{"112233445566778899", "1122334455667788" + "9980000000000000"},
	}
	for _, c := range cases {
		got := Pad3(mustHex(t, c.in), 8)
		if want := mustHex(t, c.want); !bytes.Equal(got, want) {
			t.Errorf("Pad3(%s) = %x, ожидалось %s", c.in, got, c.want)
		}
	}
}

func TestUnpad2Errors(t *testing.T) {
	for _, s := range []string{"", "0000000000000000", "1122334455667700"} {
		if _, err := Unpad2(mustHex(t, s)); err != ErrPadding {
			t.Errorf("Unpad2(%s): err = %v, ожидалось ErrPadding", s, err)
		}
	}
}

// Pad2 и Unpad2 обязаны быть обратны друг другу на любых длинах.
func TestPadRoundTrip(t *testing.T) {
	for _, bs := range []int{8, 16} {
		for n := 0; n < 3*bs+1; n++ {
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*7 + 1)
			}
			padded := Pad2(src, bs)
			if len(padded)%bs != 0 {
				t.Fatalf("Pad2: длина %d не кратна %d", len(padded), bs)
			}
			back, err := Unpad2(padded)
			if err != nil {
				t.Fatalf("Unpad2 (bs=%d, n=%d): %v", bs, n, err)
			}
			if !bytes.Equal(back, src) {
				t.Fatalf("round-trip (bs=%d, n=%d): %x != %x", bs, n, back, src)
			}
		}
	}
}

// --- бенчмарки ------------------------------------------------------------

func benchStream(b *testing.B, newStream func() cipher.Stream) {
	buf := make([]byte, 8192)
	s := newStream()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.XORKeyStream(buf, buf)
	}
}

func BenchmarkCTRKuznyechik(b *testing.B) {
	blk, _ := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	benchStream(b, func() cipher.Stream {
		s, _ := NewCTR(blk, make([]byte, kuznyechik.BlockSize/2))
		return s
	})
}

func BenchmarkCTRMagma(b *testing.B) {
	blk, _ := magma.NewCipher(make([]byte, magma.KeySize))
	benchStream(b, func() cipher.Stream {
		s, _ := NewCTR(blk, make([]byte, magma.BlockSize/2))
		return s
	})
}

func BenchmarkCFBKuznyechik(b *testing.B) {
	blk, _ := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	benchStream(b, func() cipher.Stream {
		s, _ := NewCFBEncrypter(blk, make([]byte, kuznyechik.BlockSize))
		return s
	})
}

func BenchmarkMACKuznyechik(b *testing.B) {
	blk, _ := kuznyechik.NewCipher(make([]byte, kuznyechik.KeySize))
	m, _ := NewMAC(blk, kuznyechik.BlockSize)
	buf := make([]byte, 8192)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Reset()
		m.Write(buf)
		m.Sum(nil)
	}
}
