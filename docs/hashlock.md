# Hashlock-consistency circuit

For each wire/value row r, the public statement is a SHA-256 digest h_r and a Baby Jubjub point P_r. The circuit proves, in one Groth16 proof over BN254:

$$\bigwedge_{r}\ \exists\,y_r:\quad h_r=\mathrm{SHA256}(y_r)\quad\land\quad P_r=[y_r]G.$$

In the protocol, P_r is C_r(α), which the verifier computes outside the circuit from public Feldman coefficient commitments; the circuit takes it as a public input.

**Encoding.** y_r is a private 32-byte string. SHA-256 hashes those bytes, and the group multiplication reads them as an unsigned big-endian integer using all 256 bits. There is no y_r < L constraint, so the point fixes y_r only modulo the subgroup order L: the encodings of 1 and 1 + L give the same point and different hashes, and both are accepted with their own hash. Label recovery must reduce the revealed preimage modulo L before interpolation. The digest is public as two 128-bit limbs.

**Curve.** Baby Jubjub in the reduced twisted Edwards form of [EIP-2494](https://eips.ethereum.org/EIPS/eip-2494#forms-of-the-curve) (a = −1) with the EIP's prime-subgroup base point, as in gnark-crypto. Fixed-base multiplication uses precomputed 2-bit tables and native Edwards addition. Matching the public point also fixes subgroup membership.

**Cost.** 25,502 constraints per row for SHA-256, 1,308 for the multiplication, and about 131.8K fixed constraints for SHA-256's lookup tables: 54,769,883 constraints at 1,019 wires.

**Tests.** `go test ./circuit` covers honest inputs, preimages at and above L, above the BN254 field modulus and at 2^256 − 1, the 1 / 1 + L case, and rejection of wrong hashes, points, preimages, row order and non-byte inputs. Fixtures are sampled below L by rejection from SHA-256 with a recorded seed; that is a fixture choice, not a circuit constraint.

**Running.** `bin/hashlock-bench -wires N -mode compile|check|prove -out DIR`. `-mode setup -keys DIR` writes the constraint system and keys; `-mode prove -keys DIR` then proves from them in a separate process (the raw proving key is read without subgroup checks, so only use keys you generated). `check` solves the witness with a random stand-in for gnark's commitment challenge; `prove` uses the real one. `bin/hashlock-verify --dir DIR` re-verifies a saved proof.
