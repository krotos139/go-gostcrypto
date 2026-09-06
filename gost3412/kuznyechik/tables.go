// SPDX-FileCopyrightText: 2026 IURII IAKOVLEV
// SPDX-License-Identifier: MIT

package kuznyechik

import "encoding/binary"

// Объединённые таблицы LS: подстановка S и линейное преобразование L
// свёрнуты в 16 таблиц по 256 записей.
//
//	encTable[i][x] = L(вектор, у которого в байте i стоит pi(x))
//	decTable[i][x] = L^-1(вектор, у которого в байте i стоит pi^-1(x))
//
// Тогда L(S(t)) = XOR по i от encTable[i][t_i], и весь раунд сводится к
// шестнадцати выборкам вместо шестнадцати применений R. Каждая таблица
// занимает 64 КиБ, обе вместе — 128 КиБ.
//
// Табличная реализация не защищена от атак по времени доступа к кэшу:
// индекс выборки зависит от секретных данных. См. README.
var (
	encTable [BlockSize][256][2]uint64
	decTable [BlockSize][256][2]uint64
)

func pack(b *block) [2]uint64 {
	return [2]uint64{
		binary.BigEndian.Uint64(b[0:8]),
		binary.BigEndian.Uint64(b[8:16]),
	}
}

// buildTable заполняет одну из таблиц. Преобразование linear линейно над
// GF(2), поэтому достаточно вычислить его для восьми одиночных битов в
// каждой позиции, а значения для всех 256 байт собрать сложением по
// модулю 2. Это в тридцать два раза дешевле прямого вычисления.
func buildTable(dst *[BlockSize][256][2]uint64, subst *[256]byte, linear func(*block)) {
	for i := 0; i < BlockSize; i++ {
		var basis [8]block
		for bit := 0; bit < 8; bit++ {
			var v block
			v[i] = 1 << uint(bit)
			linear(&v)
			basis[bit] = v
		}
		for x := 0; x < 256; x++ {
			var acc block
			s := subst[x]
			for bit := 0; bit < 8; bit++ {
				if s&(1<<uint(bit)) != 0 {
					xorBlock(&acc, &basis[bit])
				}
			}
			dst[i][x] = pack(&acc)
		}
	}
}

func init() {
	buildTable(&encTable, &pi, lTransform)
	buildTable(&decTable, &piInv, lTransformInv)
}

// lsx применяет объединённое преобразование по таблице tab.
func lsx(x0, x1 uint64, tab *[BlockSize][256][2]uint64) (uint64, uint64) {
	var r0, r1 uint64
	e := &tab[0][byte(x0>>56)]
	r0, r1 = e[0], e[1]
	e = &tab[1][byte(x0>>48)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[2][byte(x0>>40)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[3][byte(x0>>32)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[4][byte(x0>>24)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[5][byte(x0>>16)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[6][byte(x0>>8)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[7][byte(x0)]
	r0, r1 = r0^e[0], r1^e[1]

	e = &tab[8][byte(x1>>56)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[9][byte(x1>>48)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[10][byte(x1>>40)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[11][byte(x1>>32)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[12][byte(x1>>24)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[13][byte(x1>>16)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[14][byte(x1>>8)]
	r0, r1 = r0^e[0], r1^e[1]
	e = &tab[15][byte(x1)]
	return r0 ^ e[0], r1 ^ e[1]
}
