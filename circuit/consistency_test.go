package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	native "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestCurveMatchesEIP2494(t *testing.T) {
	p := native.GetEdwardsCurve()
	if p.Base.X.String() != "9671717474070082183213120605117400219616337014328744928644933853176787189663" ||
		p.Base.Y.String() != "16950150798460657717958625567821834550301663161624707787222815936182638968203" ||
		p.Order.String() != "2736030358979909402780800718157159386076813972158567259200215660948447373041" {
		t.Fatal("curve parameters differ from the EIP-2494 reduced-form subgroup")
	}
	var multiple native.PointAffine
	multiple.ScalarMultiplication(&p.Base, &p.Order)
	if !multiple.IsZero() || !p.Base.IsOnCurve() || p.Base.IsZero() {
		t.Fatal("invalid subgroup base point")
	}
}

func TestRelation(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, New(2))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Two rows: %d constraints", cs.GetNbConstraints())
	valid, _, err := Assignment(1, "20261001")
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, assignment *Circuit, expectValid bool) {
		t.Helper()
		w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		_, err = cs.Solve(w)
		if (err == nil) != expectValid {
			t.Fatalf("valid=%v, expected=%v: %v", err == nil, expectValid, err)
		}
	}
	t.Run("deterministic_valid", func(t *testing.T) { check(t, valid, true) })
	for name, pair := range map[string][2]*big.Int{
		"range_boundaries":     {big.NewInt(0), new(big.Int).Sub(Order(), big.NewInt(1))},
		"byte_boundaries":      {big.NewInt(1), big.NewInt(256)},
		"high_bits":            {new(big.Int).Lsh(big.NewInt(1), 128), new(big.Int).Lsh(big.NewInt(1), 250)},
		"above_subgroup_order": {Order(), new(big.Int).Add(Order(), big.NewInt(1))},
		"above_bn254_field":    {ecc.BN254.ScalarField(), new(big.Int).Add(ecc.BN254.ScalarField(), big.NewInt(1))},
		"full_256_bit_input":   {new(big.Int).Lsh(big.NewInt(1), 255), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))},
	} {
		t.Run(name, func(t *testing.T) {
			a := CopyAssignment(valid)
			for r, scalar := range pair {
				a.Preimages[r] = EncodePreimage(scalar)
				a.Public[r], _ = Statement(scalar)
			}
			check(t, a, true)
		})
	}
	for _, half := range []string{"high", "low"} {
		t.Run("wrong_hash_"+half, func(t *testing.T) {
			a := CopyAssignment(valid)
			if half == "high" {
				a.Public[0].HashHi = new(big.Int).Xor(a.Public[0].HashHi.(*big.Int), big.NewInt(1))
			} else {
				a.Public[0].HashLo = new(big.Int).Xor(a.Public[0].HashLo.(*big.Int), big.NewInt(1))
			}
			check(t, a, false)
		})
	}
	t.Run("wrong_valid_subgroup_point", func(t *testing.T) {
		a := CopyAssignment(valid)
		other, err := PreimageInteger(a.Preimages[0])
		if err != nil {
			t.Fatal(err)
		}
		other.Add(other, big.NewInt(1))
		pub, _ := Statement(other)
		a.Public[0].X, a.Public[0].Y = pub.X, pub.Y
		check(t, a, false)
	})
	t.Run("same_point_different_preimages", func(t *testing.T) {
		a := CopyAssignment(valid)
		y := big.NewInt(1)
		yPlusOrder := new(big.Int).Add(Order(), y)
		a.Preimages[0], a.Preimages[1] = EncodePreimage(y), EncodePreimage(yPlusOrder)
		var hash0, hash1 [32]byte
		a.Public[0], hash0 = Statement(y)
		a.Public[1], hash1 = Statement(yPlusOrder)
		if a.Public[0].X.(*big.Int).Cmp(a.Public[1].X.(*big.Int)) != 0 ||
			a.Public[0].Y.(*big.Int).Cmp(a.Public[1].Y.(*big.Int)) != 0 || hash0 == hash1 {
			t.Fatal("expected the same group point and different hash commitments")
		}
		check(t, a, true)
	})
	t.Run("reject_non_byte_input", func(t *testing.T) {
		a := CopyAssignment(valid)
		a.Preimages[0][0] = 256
		check(t, a, false)
	})
	t.Run("wrong_preimage", func(t *testing.T) {
		a := CopyAssignment(valid)
		a.Preimages[0][31] = a.Preimages[0][31].(uint8) ^ 1
		check(t, a, false)
	})
	t.Run("swapped_rows", func(t *testing.T) {
		a := CopyAssignment(valid)
		a.Public[0], a.Public[1] = a.Public[1], a.Public[0]
		check(t, a, false)
	})
}
