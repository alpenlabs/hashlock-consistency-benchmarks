// Command gnark component micro-benchmarks: one gadget repeated N times in a
// native Groth16/BN254 circuit. The SHA-256 and Baby Jubjub gadgets are copies of
// those in circuit/consistency.go, so per-row costs match the hashlock circuit.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	native "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	swe "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	tw "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type (
	Fp = emulated.Secp256k1Fp
	Fr = emulated.Secp256k1Fr
)

// items mirrors components/sp1/host: item i = SHA256(domain || len(seed) || seed || i).
func items(n int, seed string) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		h := sha256.New()
		h.Write([]byte("components/v1\x00"))
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(len(seed)))
		h.Write(b[:])
		h.Write([]byte(seed))
		binary.BigEndian.PutUint64(b[:], uint64(i))
		h.Write(b[:])
		copy(out[i][:], h.Sum(nil))
	}
	return out
}

func bytesVars(x [32]byte) [32]frontend.Variable {
	var v [32]frontend.Variable
	for i, b := range x {
		v[i] = b
	}
	return v
}

// --- SHA-256 of a 32-byte message (one compression), as in the hashlock row.
type ShaCircuit struct {
	In  [][32]frontend.Variable
	Out [][2]frontend.Variable `gnark:",public"`
}

func (c *ShaCircuit) Define(api frontend.API) error {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	for r, in := range c.In {
		msg := make([]uints.U8, 32)
		for i, v := range in {
			msg[i] = bapi.ValueOf(v)
		}
		h, err := sha2.New(api)
		if err != nil {
			return err
		}
		h.Write(msg)
		d := h.Sum()
		var hi, lo frontend.Variable = 0, 0
		for i := 0; i < 16; i++ {
			hi = api.Add(api.Mul(hi, 256), bapi.Value(d[i]))
			lo = api.Add(api.Mul(lo, 256), bapi.Value(d[i+16]))
		}
		api.AssertIsEqual(hi, c.Out[r][0])
		api.AssertIsEqual(lo, c.Out[r][1])
	}
	return nil
}

// --- Baby Jubjub fixed-base multiplication by a 256-bit big-endian scalar, as in the hashlock row.
type BjjCircuit struct {
	In  [][32]frontend.Variable
	Out [][2]frontend.Variable `gnark:",public"`
}

func bjjTables() [][4]tw.Point {
	params := native.GetEdwardsCurve()
	base := params.Base
	t := make([][4]tw.Point, 128)
	for i := range t {
		var p [4]native.PointAffine
		p[0].Y.SetOne()
		p[1] = base
		p[2].Double(&base)
		p[3].Add(&p[2], &base)
		for j := range p {
			t[i][j] = tw.Point{X: p[j].X.BigInt(new(big.Int)), Y: p[j].Y.BigInt(new(big.Int))}
		}
		base.Double(&p[2])
	}
	return t
}

func (c *BjjCircuit) Define(api frontend.API) error {
	curve, err := tw.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	tab := bjjTables()
	for r, in := range c.In {
		bits := make([]frontend.Variable, 256)
		for i, v := range in {
			copy(bits[8*(31-i):8*(32-i)], api.ToBinary(v, 8))
		}
		acc := tw.Point{X: 0, Y: 1}
		for i, tb := range tab {
			acc = curve.Add(acc, tw.Point{
				X: api.Lookup2(bits[2*i], bits[2*i+1], tb[0].X, tb[1].X, tb[2].X, tb[3].X),
				Y: api.Lookup2(bits[2*i], bits[2*i+1], tb[0].Y, tb[1].Y, tb[2].Y, tb[3].Y),
			})
		}
		api.AssertIsEqual(acc.X, c.Out[r][0])
		api.AssertIsEqual(acc.Y, c.Out[r][1])
	}
	return nil
}

// --- Native BN254 scalar-field multiplication chain.
type FrMulCircuit struct {
	In  []frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *FrMulCircuit) Define(api frontend.API) error {
	var acc frontend.Variable = 1
	for _, x := range c.In {
		acc = api.Mul(acc, x)
	}
	api.AssertIsEqual(acc, c.Out)
	return nil
}

// --- 128-bit XOR (soldering's label delta), bytes via lookup-based XOR, output packed.
type XorCircuit struct {
	In  [][32]frontend.Variable
	Out []frontend.Variable `gnark:",public"`
}

func (c *XorCircuit) Define(api frontend.API) error {
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	for r, in := range c.In {
		var packed frontend.Variable = 0
		for i := 15; i >= 0; i-- {
			d := bapi.Xor(bapi.ValueOf(in[i]), bapi.ValueOf(in[16+i]))
			packed = api.Add(api.Mul(packed, 256), bapi.Value(d))
		}
		api.AssertIsEqual(packed, c.Out[r])
	}
	return nil
}

// --- secp256k1 fixed-base multiplication with emulated (non-native) field arithmetic.
type SecpCircuit struct {
	S    []emulated.Element[Fr]
	X, Y []emulated.Element[Fp] `gnark:",public"`
}

func (c *SecpCircuit) Define(api frontend.API) error {
	curve, err := swe.New[Fp, Fr](api, swe.GetSecp256k1Params())
	if err != nil {
		return err
	}
	for i := range c.S {
		p := curve.ScalarMulBase(&c.S[i])
		curve.AssertIsEqual(p, &swe.AffinePoint[Fp]{X: c.X[i], Y: c.Y[i]})
	}
	return nil
}

func bjjPoint(x [32]byte) (*big.Int, *big.Int) {
	params := native.GetEdwardsCurve()
	var p native.PointAffine
	p.ScalarMultiplication(&params.Base, new(big.Int).SetBytes(x[:]))
	return p.X.BigInt(new(big.Int)), p.Y.BigInt(new(big.Int))
}

// circuits returns the empty circuit and its assignment for op over the given items.
func circuits(op string, xs [][32]byte) (frontend.Circuit, frontend.Circuit, error) {
	n := len(xs)
	switch op {
	case "sha256":
		c, a := &ShaCircuit{In: make([][32]frontend.Variable, n), Out: make([][2]frontend.Variable, n)},
			&ShaCircuit{In: make([][32]frontend.Variable, n), Out: make([][2]frontend.Variable, n)}
		for i, x := range xs {
			d := sha256.Sum256(x[:])
			a.In[i] = bytesVars(x)
			a.Out[i] = [2]frontend.Variable{new(big.Int).SetBytes(d[:16]), new(big.Int).SetBytes(d[16:])}
		}
		return c, a, nil
	case "bjj-fixed-base-mul":
		c, a := &BjjCircuit{In: make([][32]frontend.Variable, n), Out: make([][2]frontend.Variable, n)},
			&BjjCircuit{In: make([][32]frontend.Variable, n), Out: make([][2]frontend.Variable, n)}
		for i, x := range xs {
			px, py := bjjPoint(x)
			a.In[i] = bytesVars(x)
			a.Out[i] = [2]frontend.Variable{px, py}
		}
		return c, a, nil
	case "fr-mul":
		c, a := &FrMulCircuit{In: make([]frontend.Variable, n)}, &FrMulCircuit{In: make([]frontend.Variable, n)}
		var acc bnfr.Element
		acc.SetOne()
		for i, x := range xs {
			var e bnfr.Element
			e.SetBytes(x[:])
			acc.Mul(&acc, &e)
			a.In[i] = e.BigInt(new(big.Int))
		}
		a.Out = acc.BigInt(new(big.Int))
		return c, a, nil
	case "xor128":
		c, a := &XorCircuit{In: make([][32]frontend.Variable, n), Out: make([]frontend.Variable, n)},
			&XorCircuit{In: make([][32]frontend.Variable, n), Out: make([]frontend.Variable, n)}
		for i, x := range xs {
			var d [16]byte
			for j := range d {
				d[j] = x[j] ^ x[16+j]
			}
			// Little-endian packing, matching the circuit.
			for l, r := 0, 15; l < r; l, r = l+1, r-1 {
				d[l], d[r] = d[r], d[l]
			}
			a.In[i] = bytesVars(x)
			a.Out[i] = new(big.Int).SetBytes(d[:])
		}
		return c, a, nil
	case "secp256k1-fixed-base-mul":
		c := &SecpCircuit{S: make([]emulated.Element[Fr], n), X: make([]emulated.Element[Fp], n), Y: make([]emulated.Element[Fp], n)}
		a := &SecpCircuit{S: make([]emulated.Element[Fr], n), X: make([]emulated.Element[Fp], n), Y: make([]emulated.Element[Fp], n)}
		order := secp256k1.ID.ScalarField()
		for i, x := range xs {
			s := new(big.Int).Mod(new(big.Int).SetBytes(x[:]), order)
			var p secp256k1.G1Affine
			p.ScalarMultiplicationBase(s)
			a.S[i] = emulated.ValueOf[Fr](s)
			a.X[i] = emulated.ValueOf[Fp](p.X.BigInt(new(big.Int)))
			a.Y[i] = emulated.ValueOf[Fp](p.Y.BigInt(new(big.Int)))
		}
		return c, a, nil
	}
	return nil, nil, fmt.Errorf("unknown op %q", op)
}

func oracle(args []string) error {
	fs := flag.NewFlagSet("oracle", flag.ExitOnError)
	op := fs.String("op", "bjj-fixed-base-mul", "only bjj-fixed-base-mul")
	n := fs.Int("n", 1, "repetitions")
	seed := fs.String("seed", "20261002", "item seed")
	fs.Parse(args)
	if *op != "bjj-fixed-base-mul" {
		return fmt.Errorf("oracle supports only bjj-fixed-base-mul")
	}
	// XOR-fold of the 32-byte big-endian coordinates, as the SP1 guest commits.
	var fx, fy [32]byte
	for _, x := range items(*n, *seed) {
		px, py := bjjPoint(x)
		var bx, by [32]byte
		px.FillBytes(bx[:])
		py.FillBytes(by[:])
		for i := range fx {
			fx[i] ^= bx[i]
			fy[i] ^= by[i]
		}
	}
	fmt.Println(hex.EncodeToString(append(fx[:], fy[:]...)))
	return nil
}

func bench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	op := fs.String("op", "sha256", "sha256, bjj-fixed-base-mul, fr-mul, xor128, secp256k1-fixed-base-mul")
	n := fs.Int("n", 1, "repetitions")
	seed := fs.String("seed", "20261002", "item seed")
	mode := fs.String("mode", "compile", "compile or prove")
	out := fs.String("out", "", "new output directory")
	fs.Parse(args)
	if *out == "" || (*mode != "compile" && *mode != "prove") {
		return fmt.Errorf("-out and -mode compile|prove are required")
	}
	if err := os.Mkdir(*out, 0o755); err != nil {
		return err
	}
	rec := map[string]any{"approach": "components-gnark", "op": *op, "n": *n, "mode": *mode, "seed": *seed,
		"cpu_workers": runtime.GOMAXPROCS(0), "go_version": runtime.Version(), "status": "running"}
	times := map[string]float64{}
	rec["timings_s"] = times
	save := func() error {
		b, _ := json.MarshalIndent(rec, "", "  ")
		return os.WriteFile(filepath.Join(*out, "result.json"), append(b, '\n'), 0o644)
	}
	timed := func(name string, f func() error) error {
		fmt.Fprintf(os.Stderr, "stage=%s status=started\n", name)
		t := time.Now()
		err := f()
		times[name] = time.Since(t).Seconds()
		fmt.Fprintf(os.Stderr, "stage=%s status=finished seconds=%.6f\n", name, times[name])
		_ = save()
		return err
	}
	circuit, assignment, err := circuits(*op, items(*n, *seed))
	if err != nil {
		return err
	}
	var compiled constraint.ConstraintSystem
	if err := timed("compile", func() (err error) {
		compiled, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		return err
	}); err != nil {
		return err
	}
	rec["constraints"], rec["internal_variables"] = compiled.GetNbConstraints(), compiled.GetNbInternalVariables()
	if *mode == "prove" {
		full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		public, err := full.Public()
		if err != nil {
			return err
		}
		var pk groth16.ProvingKey
		var vk groth16.VerifyingKey
		if err := timed("setup", func() (err error) { pk, vk, err = groth16.Setup(compiled); return err }); err != nil {
			return err
		}
		var proof groth16.Proof
		if err := timed("prove", func() (err error) { proof, err = groth16.Prove(compiled, pk, full); return err }); err != nil {
			return err
		}
		if err := timed("verify", func() error { return groth16.Verify(proof, vk, public) }); err != nil {
			return err
		}
		rec["proof_verified"] = true
		// Sanity check: the proof must not verify against a changed public input.
		vec := public.Vector().(bnfr.Vector)
		var one bnfr.Element
		one.SetOne()
		vec[0].Add(&vec[0], &one)
		rec["tampered_public_rejected"] = groth16.Verify(proof, vk, public) != nil
		if rec["tampered_public_rejected"] != true {
			return fmt.Errorf("proof verified against a changed public input")
		}
	}
	rec["status"] = "complete"
	return save()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: components-gnark bench|oracle [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bench":
		err = bench(os.Args[2:])
	case "oracle":
		err = oracle(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
