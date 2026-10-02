package circuit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	native "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type StatementRow struct {
	Wire   int    `json:"wire"`
	Value  int    `json:"value"`
	X      string `json:"point_x"`
	Y      string `json:"point_y"`
	SHA256 string `json:"sha256"`
}

func EncodePreimage(integer *big.Int) Preimage {
	if integer.Sign() < 0 || integer.BitLen() > 256 {
		panic("preimage integer must fit an unsigned 32-byte string")
	}
	var encoded [32]byte
	integer.FillBytes(encoded[:])
	var result Preimage
	for i, value := range encoded {
		result[i] = value
	}
	return result
}

// PreimageInteger decodes a concrete fixture, not symbolic circuit variables.
func PreimageInteger(preimage Preimage) (*big.Int, error) {
	var encoded [32]byte
	for i, value := range preimage {
		b, ok := value.(uint8)
		if !ok {
			return nil, fmt.Errorf("fixture preimage byte %d has type %T, expected uint8", i, value)
		}
		encoded[i] = b
	}
	return new(big.Int).SetBytes(encoded[:]), nil
}

// Statement computes both equalities with native curve arithmetic and the
// standard library hash. Every unsigned 256-bit preimage integer is allowed.
func Statement(scalar *big.Int) (PublicRow, [32]byte) {
	if scalar.Sign() < 0 || scalar.BitLen() > 256 {
		panic("scalar must fit an unsigned 32-byte string")
	}
	var encoded [32]byte
	scalar.FillBytes(encoded[:])
	digest := sha256.Sum256(encoded[:])
	params := native.GetEdwardsCurve()
	var point native.PointAffine
	point.ScalarMultiplication(&params.Base, scalar)
	return PublicRow{
		X: point.X.BigInt(new(big.Int)), Y: point.Y.BigInt(new(big.Int)),
		HashHi: new(big.Int).SetBytes(digest[:16]),
		HashLo: new(big.Int).SetBytes(digest[16:]),
	}, digest
}

// Deterministic rejection sampling is for synthetic benchmark witnesses only.
func sample(seed string, row uint64) *big.Int {
	order := Order()
	for counter := uint64(0); ; counter++ {
		h := sha256.New()
		h.Write([]byte("hashlock-consistency-bench/v1\x00"))
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(len(seed)))
		h.Write(encoded[:])
		h.Write([]byte(seed))
		binary.BigEndian.PutUint64(encoded[:], row)
		h.Write(encoded[:])
		binary.BigEndian.PutUint64(encoded[:], counter)
		h.Write(encoded[:])
		bytes := h.Sum(nil)
		bytes[0] &= 0x07 // 251 bits; reject rather than reduce modulo the order.
		candidate := new(big.Int).SetBytes(bytes)
		if candidate.Cmp(order) < 0 {
			return candidate
		}
	}
}

func Assignment(wires int, seed string) (*Circuit, []StatementRow, error) {
	if wires < 1 || wires > int(^uint(0)>>1)/2 {
		return nil, nil, fmt.Errorf("invalid wire count")
	}
	assignment := New(2 * wires)
	rows := make([]StatementRow, len(assignment.Public))
	for r := range assignment.Preimages {
		scalar := sample(seed, uint64(r))
		public, digest := Statement(scalar)
		assignment.Preimages[r], assignment.Public[r] = EncodePreimage(scalar), public
		rows[r] = StatementRow{Wire: r / 2, Value: r % 2,
			X: public.X.(*big.Int).String(), Y: public.Y.(*big.Int).String(), SHA256: hex.EncodeToString(digest[:])}
	}
	return assignment, rows, nil
}

func CopyAssignment(src *Circuit) *Circuit {
	dst := New(len(src.Preimages))
	copy(dst.Preimages, src.Preimages)
	copy(dst.Public, src.Public)
	return dst
}
