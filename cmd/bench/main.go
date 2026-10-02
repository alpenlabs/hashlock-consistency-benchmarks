package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"hashlock-consistency-bench/circuit"
)

type recorder struct {
	out   string
	data  map[string]any
	times map[string]float64
}

// Check mode only: gnark's solver refuses the commitment placeholder outside tests,
// so supply a random challenge. Proving always uses the real commitment.
func diagnosticCommitment(field *big.Int, _ []*big.Int, out []*big.Int) error {
	if len(out) != 1 {
		return fmt.Errorf("expected one diagnostic commitment challenge")
	}
	for {
		challenge, err := rand.Int(rand.Reader, field)
		if err != nil {
			return err
		}
		if challenge.Sign() != 0 {
			out[0].Set(challenge)
			return nil
		}
	}
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func (r *recorder) save() error {
	tmp := filepath.Join(r.out, "result.json.tmp")
	if err := writeJSON(tmp, r.data); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.out, "result.json"))
}

func (r *recorder) stage(name string, f func() error) error {
	r.data["active_stage"] = name
	if err := r.save(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "stage=%s status=started\n", name)
	start := time.Now()
	err := f()
	r.times[name] = time.Since(start).Seconds()
	if err != nil {
		r.data["status"], r.data["error"] = "failed", err.Error()
	} else {
		fmt.Fprintf(os.Stderr, "stage=%s status=finished seconds=%.6f\n", name, r.times[name])
	}
	if saveErr := r.save(); saveErr != nil {
		return saveErr
	}
	return err
}

func writeArtifact(out, name string, value io.WriterTo, sizes map[string]int64) error {
	f, err := os.OpenFile(filepath.Join(out, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	n, err := value.WriteTo(f)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	sizes[name] = n
	return nil
}

// Buffered so that large keys are not written one curve point per syscall.
func writeKeyFile(path string, write func(io.Writer) (int64, error), sizes map[string]int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	n, err := write(w)
	if err == nil {
		err = w.Flush()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		sizes[filepath.Base(path)] = n
	}
	return err
}

func readKeyFile(path string, read func(io.Reader) (int64, error)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	if _, err := read(r); err != nil {
		return err
	}
	if _, err := r.ReadByte(); err != io.EOF {
		return fmt.Errorf("trailing bytes in %s", filepath.Base(path))
	}
	return nil
}

func run() error {
	wires := flag.Int("wires", 1, "number of bit wires (two rows per wire)")
	mode := flag.String("mode", "check", "compile, check, setup, or prove")
	seed := flag.String("seed", "20261001", "deterministic synthetic witness seed")
	out := flag.String("out", "", "new output directory (required)")
	keys := flag.String("keys", "", "key directory: setup writes it; prove reads it instead of compiling and generating keys")
	flag.Parse()
	if *wires < 1 || *wires > int(^uint(0)>>1)/2 || *out == "" {
		return fmt.Errorf("positive --wires and --out are required")
	}
	if *mode != "compile" && *mode != "check" && *mode != "setup" && *mode != "prove" {
		return fmt.Errorf("invalid mode")
	}
	if *mode == "setup" && *keys == "" {
		return fmt.Errorf("setup mode requires -keys")
	}
	if *keys != "" && *mode != "setup" && *mode != "prove" {
		return fmt.Errorf("-keys applies only to setup and prove")
	}
	if err := os.Mkdir(*out, 0o755); err != nil {
		return err
	}
	times := make(map[string]float64)
	sizes := make(map[string]int64)
	info, _ := debug.ReadBuildInfo()
	r := &recorder{out: *out, times: times, data: map[string]any{
		"schema_version": 2, "status": "running", "mode": *mode,
		"wires": *wires, "rows_per_wire": 2, "rows": 2 * *wires,
		"seed": *seed, "hash": "SHA-256", "scalar_encoding": "unsigned 32-byte big-endian; no y < L condition",
		"scalar_range_check": false, "preimage_bits": 256,
		"group":        "EIP-2494 Baby Jubjub, reduced twisted Edwards form, prime subgroup",
		"scalar_order": circuit.Order().String(), "proof_system": "native Groth16 / BN254 / gnark v0.14.0",
		"fixed_base_method": "two-bit constant table, native Edwards addition",
		"cpu_workers":       runtime.GOMAXPROCS(0), "go_version": runtime.Version(),
		"go_build_info": info, "timings_s": times, "artifact_bytes": sizes,
		"proof_verified": false, "trusted_setup": "local circuit-specific test CRS",
		"scope":    "hash/group consistency only; polynomial evaluation points supplied as public inputs",
		"keys_dir": *keys, "key_generation_in_this_process": *mode == "setup" || (*mode == "prove" && *keys == ""),
	}}
	if err := r.save(); err != nil {
		return err
	}
	var cs constraint.ConstraintSystem
	if *mode == "prove" && *keys != "" {
		if err := r.stage("load_constraint_system", func() error {
			cs = groth16.NewCS(ecc.BN254)
			return readKeyFile(filepath.Join(*keys, "constraint-system.bin"), cs.ReadFrom)
		}); err != nil {
			return err
		}
	} else if err := r.stage("compile", func() (err error) {
		cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit.New(2**wires))
		return err
	}); err != nil {
		return err
	}
	r.data["constraints"] = cs.GetNbConstraints()
	r.data["public_variables_including_constant"] = cs.GetNbPublicVariables()
	r.data["secret_variables"] = cs.GetNbSecretVariables()
	r.data["internal_variables"] = cs.GetNbInternalVariables()
	if *mode == "setup" {
		if err := os.Mkdir(*keys, 0o755); err != nil {
			return err
		}
		var pk groth16.ProvingKey
		var vk groth16.VerifyingKey
		if err := r.stage("setup", func() (err error) { pk, vk, err = groth16.Setup(cs); return err }); err != nil {
			return err
		}
		r.data["proving_key_g1_elements"], r.data["proving_key_g2_elements"] = pk.NbG1(), pk.NbG2()
		if err := r.stage("write_keys", func() error {
			for _, item := range []struct {
				name  string
				write func(io.Writer) (int64, error)
			}{
				{"constraint-system.bin", cs.WriteTo}, {"proving-key.raw.bin", pk.WriteRawTo}, {"verifying-key.bin", vk.WriteTo},
			} {
				if err := writeKeyFile(filepath.Join(*keys, item.name), item.write, sizes); err != nil {
					return err
				}
			}
			n, err := pk.WriteTo(io.Discard)
			sizes["proving-key-serialized-not-saved"] = n
			return err
		}); err != nil {
			return err
		}
	} else if *mode != "compile" {
		var assignment *circuit.Circuit
		var rows []circuit.StatementRow
		if err := r.stage("host_fixture", func() (err error) {
			assignment, rows, err = circuit.Assignment(*wires, *seed)
			return err
		}); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(*out, "statement.json"), rows); err != nil {
			return err
		}
		var full, public witness.Witness
		if err := r.stage("witness", func() (err error) {
			full, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				return err
			}
			public, err = full.Public()
			return err
		}); err != nil {
			return err
		}
		if *mode == "check" {
			r.data["check_commitment_mode"] = "random challenge for solver diagnostics only; not a proof"
			if err := r.stage("solve", func() error {
				_, err := cs.Solve(full, solver.OverrideHint(solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder), diagnosticCommitment))
				return err
			}); err != nil {
				return err
			}
			r.data["constraints_satisfied"] = true
		} else {
			var pk groth16.ProvingKey
			var vk groth16.VerifyingKey
			if *keys == "" {
				if err := r.stage("setup", func() (err error) { pk, vk, err = groth16.Setup(cs); return err }); err != nil {
					return err
				}
			} else if err := r.stage("load_keys", func() error {
				pk, vk = groth16.NewProvingKey(ecc.BN254), groth16.NewVerifyingKey(ecc.BN254)
				// Unchecked raw decoding: setup mode wrote these keys.
				if err := readKeyFile(filepath.Join(*keys, "proving-key.raw.bin"), pk.UnsafeReadFrom); err != nil {
					return err
				}
				return readKeyFile(filepath.Join(*keys, "verifying-key.bin"), vk.ReadFrom)
			}); err != nil {
				return err
			}
			r.data["proving_key_g1_elements"], r.data["proving_key_g2_elements"] = pk.NbG1(), pk.NbG2()
			var proof groth16.Proof
			if err := r.stage("prove", func() (err error) { proof, err = groth16.Prove(cs, pk, full); return err }); err != nil {
				return err
			}
			if err := r.stage("verify", func() error { return groth16.Verify(proof, vk, public) }); err != nil {
				return err
			}
			r.data["proof_verified"] = true
			if err := r.stage("negative_verification", func() error {
				for _, change := range []string{"hash", "point"} {
					bad := circuit.CopyAssignment(assignment)
					if change == "hash" {
						bad.Public[0].HashHi = new(big.Int).Xor(bad.Public[0].HashHi.(*big.Int), big.NewInt(1))
					} else {
						scalar, err := circuit.PreimageInteger(bad.Preimages[0])
						if err != nil {
							return err
						}
						scalar.Add(scalar, big.NewInt(1))
						point, _ := circuit.Statement(scalar)
						bad.Public[0].X, bad.Public[0].Y = point.X, point.Y
					}
					badPublic, err := frontend.NewWitness(bad, ecc.BN254.ScalarField(), frontend.PublicOnly())
					if err != nil {
						return err
					}
					if groth16.Verify(proof, vk, badPublic) == nil {
						return fmt.Errorf("proof accepted altered public %s", change)
					}
				}
				return nil
			}); err != nil {
				return err
			}
			r.data["altered_hash_rejected"], r.data["altered_point_rejected"] = true, true
			if err := r.stage("serialize", func() error {
				for _, item := range []struct {
					name  string
					value io.WriterTo
				}{
					{"proof.bin", proof}, {"verification-key.bin", vk}, {"public-witness.bin", public},
				} {
					if err := writeArtifact(*out, item.name, item.value, sizes); err != nil {
						return err
					}
				}
				// Measure the encoded key size without keeping the file.
				n, err := pk.WriteTo(io.Discard)
				sizes["proving-key-serialized-not-saved"] = n
				return err
			}); err != nil {
				return err
			}
		}
	}
	r.data["status"], r.data["active_stage"] = "complete", nil
	if err := r.save(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(r.data)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
