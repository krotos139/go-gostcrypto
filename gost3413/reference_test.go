// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package gost3413

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

// Контрольные примеры приложения А используют s = n: стандарт прямо
// говорит, что "параметр s выбран равным n с целью упрощения проводимых
// вычислений". Поэтому пути с s < n официальными векторами не покрыты, и
// ошибка вида "сдвигать регистр на n вместо s" в CFB прошла бы незамеченной.
//
// Здесь записана вторая, независимая реализация — буквально по формулам
// раздела 5, без потоковой буферизации. Сначала она сверяется с
// официальными векторами, а затем служит оракулом для s < n.

func refCTR(b cipher.Block, iv []byte, s int, in []byte) []byte {
	bs := b.BlockSize()
	ctr := make([]byte, bs)
	copy(ctr, iv) // CTR_1 = IV || 0^(n/2)
	out := make([]byte, len(in))
	gamma := make([]byte, bs)

	for off := 0; off < len(in); off += s {
		end := min(off+s, len(in))
		b.Encrypt(gamma, ctr)
		for i := off; i < end; i++ {
			out[i] = in[i] ^ gamma[i-off]
		}
		for j := bs - 1; j >= 0; j-- { // Add
			ctr[j]++
			if ctr[j] != 0 {
				break
			}
		}
	}
	return out
}

func refOFB(b cipher.Block, iv []byte, s int, in []byte) []byte {
	bs := b.BlockSize()
	r := dup(iv)
	out := make([]byte, len(in))
	y := make([]byte, bs)

	for off := 0; off < len(in); off += s {
		end := min(off+s, len(in))
		b.Encrypt(y, r[:bs]) // Y_i = e_K(MSB_n(R_i))
		for i := off; i < end; i++ {
			out[i] = in[i] ^ y[i-off]
		}
		copy(r, r[bs:]) // R_{i+1} = LSB_{m-n}(R_i) || Y_i
		copy(r[len(r)-bs:], y)
	}
	return out
}

func refCFB(b cipher.Block, iv []byte, s int, in []byte, decrypt bool) []byte {
	bs := b.BlockSize()
	r := dup(iv)
	out := make([]byte, len(in))
	gamma := make([]byte, bs)

	for off := 0; off < len(in); off += s {
		end := min(off+s, len(in))
		b.Encrypt(gamma, r[:bs])
		for i := off; i < end; i++ {
			out[i] = in[i] ^ gamma[i-off]
		}
		// В обратную связь уходит шифртекст.
		ct := out[off:end]
		if decrypt {
			ct = in[off:end]
		}
		if len(ct) == s { // неполный последний блок регистр уже не меняет
			copy(r, r[s:]) // R_{i+1} = LSB_{m-s}(R_i) || C_i
			copy(r[len(r)-s:], ct)
		}
	}
	return out
}

func refCBC(b cipher.Block, iv []byte, in []byte, decrypt bool) []byte {
	bs := b.BlockSize()
	r := dup(iv)
	out := make([]byte, len(in))
	tmp := make([]byte, bs)

	for off := 0; off < len(in); off += bs {
		blk := in[off : off+bs]
		if decrypt {
			b.Decrypt(tmp, blk)
			for i := 0; i < bs; i++ {
				out[off+i] = tmp[i] ^ r[i]
			}
		} else {
			for i := 0; i < bs; i++ {
				tmp[i] = blk[i] ^ r[i]
			}
			b.Encrypt(out[off:off+bs], tmp)
		}
		ct := blk
		if !decrypt {
			ct = out[off : off+bs]
		}
		copy(r, r[bs:]) // R_{i+1} = LSB_{m-n}(R_i) || C_i
		copy(r[len(r)-bs:], ct)
	}
	return out
}

// Сначала оракул сам обязан воспроизвести официальные векторы — иначе
// сверяться с ним бессмысленно.
func TestReferenceMatchesKAT(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)
			bs := b.BlockSize()
			plain := mustHex(t, v.plain)

			if got, want := refCTR(b, mustHex(t, v.ctrIV), bs, plain), mustHex(t, v.ctr); !bytes.Equal(got, want) {
				t.Errorf("оракул CTR = %x, ожидалось %x", got, want)
			}
			if got, want := refOFB(b, mustHex(t, v.ofbIV), bs, plain), mustHex(t, v.ofb); !bytes.Equal(got, want) {
				t.Errorf("оракул OFB = %x, ожидалось %x", got, want)
			}
			if got, want := refCFB(b, mustHex(t, v.cfbIV), bs, plain, false), mustHex(t, v.cfb); !bytes.Equal(got, want) {
				t.Errorf("оракул CFB = %x, ожидалось %x", got, want)
			}
			if got, want := refCBC(b, mustHex(t, v.cbcIV), plain, false), mustHex(t, v.cbc); !bytes.Equal(got, want) {
				t.Errorf("оракул CBC = %x, ожидалось %x", got, want)
			}
		})
	}
}

func testData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

func testIV(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*17 + 3)
	}
	return b
}

// Основной смысл файла: проверить поведение при s < n, где официальных
// векторов нет.
func TestSmallSMatchesReference(t *testing.T) {
	lengths := []int{0, 1, 5, 16, 17, 40, 64, 100}

	for _, v := range allVectors {
		b := v.block(t)
		bs := b.BlockSize()

		sValues := []int{1, 2, bs / 2, bs - 1, bs}
		zValues := []int{1, 2, 3}

		t.Run(v.name+"/ctr", func(t *testing.T) {
			for _, s := range sValues {
				iv := testIV(bs / 2)
				for _, n := range lengths {
					in := testData(n)
					st, err := NewCTRWithS(b, iv, s)
					if err != nil {
						t.Fatalf("s=%d: %v", s, err)
					}
					got := make([]byte, n)
					st.XORKeyStream(got, in)
					if want := refCTR(b, iv, s, in); !bytes.Equal(got, want) {
						t.Fatalf("s=%d n=%d: %x, оракул даёт %x", s, n, got, want)
					}
				}
			}
		})

		t.Run(v.name+"/ofb", func(t *testing.T) {
			for _, s := range sValues {
				for _, z := range zValues {
					iv := testIV(bs * z)
					for _, n := range lengths {
						in := testData(n)
						st, err := NewOFBWithS(b, iv, s)
						if err != nil {
							t.Fatalf("s=%d z=%d: %v", s, z, err)
						}
						got := make([]byte, n)
						st.XORKeyStream(got, in)
						if want := refOFB(b, iv, s, in); !bytes.Equal(got, want) {
							t.Fatalf("s=%d z=%d n=%d: %x, оракул даёт %x", s, z, n, got, want)
						}
					}
				}
			}
		})

		t.Run(v.name+"/cfb", func(t *testing.T) {
			for _, s := range sValues {
				for _, m := range []int{bs, bs + 1, 2 * bs, 3 * bs} {
					iv := testIV(m)
					for _, n := range lengths {
						in := testData(n)

						enc, err := NewCFBEncrypterWithS(b, iv, s)
						if err != nil {
							t.Fatalf("s=%d m=%d: %v", s, m, err)
						}
						got := make([]byte, n)
						enc.XORKeyStream(got, in)
						want := refCFB(b, iv, s, in, false)
						if !bytes.Equal(got, want) {
							t.Fatalf("enc s=%d m=%d n=%d: %x, оракул даёт %x", s, m, n, got, want)
						}

						dec, err := NewCFBDecrypterWithS(b, iv, s)
						if err != nil {
							t.Fatal(err)
						}
						back := make([]byte, n)
						dec.XORKeyStream(back, got)
						if !bytes.Equal(back, in) {
							t.Fatalf("dec s=%d m=%d n=%d: round-trip дал %x, ожидалось %x", s, m, n, back, in)
						}
					}
				}
			}
		})

		t.Run(v.name+"/cbc", func(t *testing.T) {
			for _, z := range zValues {
				iv := testIV(bs * z)
				for _, blocks := range []int{0, 1, 2, 3, 7} {
					in := testData(bs * blocks)

					enc, err := NewCBCEncrypter(b, iv)
					if err != nil {
						t.Fatalf("z=%d: %v", z, err)
					}
					got := make([]byte, len(in))
					enc.CryptBlocks(got, in)
					if want := refCBC(b, iv, in, false); !bytes.Equal(got, want) {
						t.Fatalf("z=%d blocks=%d: %x, оракул даёт %x", z, blocks, got, want)
					}

					dec, err := NewCBCDecrypter(b, iv)
					if err != nil {
						t.Fatal(err)
					}
					back := make([]byte, len(got))
					dec.CryptBlocks(back, got)
					if !bytes.Equal(back, in) {
						t.Fatalf("z=%d blocks=%d: round-trip дал %x, ожидалось %x", z, blocks, back, in)
					}
				}
			}
		})
	}
}

// Регрессия на конкретную ошибку: CFB обязан сдвигать регистр на s, а не на
// n. При s = n эти варианты неразличимы, поэтому проверяем при s < n и
// m > n, где они расходятся.
func TestCFBShiftsByS(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.name, func(t *testing.T) {
			b := v.block(t)
			bs := b.BlockSize()
			s := bs / 2
			iv := testIV(2 * bs)
			in := testData(4 * bs)

			st, err := NewCFBEncrypterWithS(b, iv, s)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(in))
			st.XORKeyStream(got, in)

			bySmallS := refCFB(b, iv, s, in, false)
			if !bytes.Equal(got, bySmallS) {
				t.Fatalf("сдвиг на s: %x, ожидалось %x", got, bySmallS)
			}
			// Если бы регистр сдвигался на n, результат отличался бы —
			// убеждаемся, что тест действительно различает эти случаи.
			byN := refCFBShiftByN(b, iv, s, in)
			if bytes.Equal(bySmallS, byN) {
				t.Fatal("тест не различает сдвиг на s и на n — проверка бесполезна")
			}
		})
	}
}

// refCFBShiftByN — намеренно неверный вариант: регистр сдвигается на n.
// Используется только чтобы убедиться, что TestCFBShiftsByS различает
// правильное и неправильное поведение.
func refCFBShiftByN(b cipher.Block, iv []byte, s int, in []byte) []byte {
	bs := b.BlockSize()
	r := dup(iv)
	out := make([]byte, len(in))
	gamma := make([]byte, bs)
	fb := make([]byte, bs)

	for off := 0; off < len(in); off += s {
		end := min(off+s, len(in))
		b.Encrypt(gamma, r[:bs])
		for i := off; i < end; i++ {
			out[i] = in[i] ^ gamma[i-off]
		}
		if end-off == s {
			copy(fb, out[off:end])
			copy(r, r[bs:])
			copy(r[len(r)-bs:], fb)
		}
	}
	return out
}
