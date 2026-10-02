package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	native "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	ed "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// PublicRow is one statement (P = y*G, h = SHA256(BE32(y))). Packing each
// digest half into 128 bits preserves the full hash in the BN254 scalar field.
type PublicRow struct {
	X, Y, HashHi, HashLo frontend.Variable
}

// Preimage is the exact 32-byte SHA-256 input, interpreted as an unsigned
// big-endian integer for group multiplication. It is not required to be < L.
type Preimage [32]frontend.Variable

type Circuit struct {
	Preimages []Preimage
	Public    []PublicRow `gnark:",public"`
}

func New(rows int) *Circuit {
	return &Circuit{Preimages: make([]Preimage, rows), Public: make([]PublicRow, rows)}
}

func Order() *big.Int {
	params := native.GetEdwardsCurve()
	return new(big.Int).Set(&params.Order)
}

// Public constants {0,1,2,3} * 4^i * G, one table per 2-bit window.
func fixedBaseTable() [][4]ed.Point {
	params := native.GetEdwardsCurve()
	base := params.Base
	tables := make([][4]ed.Point, 256/2)
	for i := range tables {
		var points [4]native.PointAffine
		points[0].Y.SetOne()
		points[1] = base
		points[2].Double(&base)
		points[3].Add(&points[2], &base)
		for j := range points {
			tables[i][j] = ed.Point{
				X: points[j].X.BigInt(new(big.Int)),
				Y: points[j].Y.BigInt(new(big.Int)),
			}
		}
		base.Double(&points[2])
	}
	return tables
}

func fixedBaseMul(api frontend.API, curve ed.Curve, bits []frontend.Variable, tables [][4]ed.Point) ed.Point {
	acc := ed.Point{X: 0, Y: 1}
	for i, table := range tables {
		low := bits[2*i]
		var high frontend.Variable = 0
		if 2*i+1 < len(bits) {
			high = bits[2*i+1]
		}
		point := ed.Point{
			X: api.Lookup2(low, high, table[0].X, table[1].X, table[2].X, table[3].X),
			Y: api.Lookup2(low, high, table[0].Y, table[1].Y, table[2].Y, table[3].Y),
		}
		acc = curve.Add(acc, point)
	}
	return acc
}

func (c *Circuit) Define(api frontend.API) error {
	if len(c.Preimages) == 0 || len(c.Preimages) != len(c.Public) {
		return fmt.Errorf("need equally sized, nonempty witness and public row lists")
	}
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		return fmt.Errorf("this circuit requires the BN254 scalar field")
	}
	curve, err := ed.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	tables := fixedBaseTable()
	for r, preimage := range c.Preimages {
		// Keep 32 byte variables: one BN254 element cannot hold all 256 bits.
		message := make([]uints.U8, len(preimage))
		bits := make([]frontend.Variable, 256)
		for i, value := range preimage {
			byteBits := api.ToBinary(value, 8)
			copy(bits[8*(31-i):8*(32-i)], byteBits)
			message[i] = byteAPI.ValueOf(value)
		}
		// No y < L check: y and y+L give the same point, so P fixes y only modulo L.
		// Label recovery must reduce the revealed preimage modulo L.
		point := fixedBaseMul(api, curve, bits, tables)
		api.AssertIsEqual(point.X, c.Public[r].X)
		api.AssertIsEqual(point.Y, c.Public[r].Y)
		// Equality to this fixed-base subgroup multiple also fixes point membership.
		hasher, err := sha2.New(api)
		if err != nil {
			return err
		}
		hasher.Write(message)
		digest := hasher.Sum()
		var hi, lo frontend.Variable = 0, 0
		for i := 0; i < 16; i++ {
			hi = api.Add(api.Mul(hi, 256), byteAPI.Value(digest[i]))
			lo = api.Add(api.Mul(lo, 256), byteAPI.Value(digest[i+16]))
		}
		api.AssertIsEqual(hi, c.Public[r].HashHi)
		api.AssertIsEqual(lo, c.Public[r].HashLo)
	}
	return nil
}
