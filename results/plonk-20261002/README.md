# Hashlock circuit with gnark PLONK

Same circuit as the Groth16 runs, compiled with `bin/hashlock-bench -backend plonk` (gnark v0.14.0, KZG over BN254, 12 threads). The reference string is gnark's unsafe test SRS, which costs the same to use as a ceremony SRS of the same size. All proofs verified and rejected an altered hash and an altered point.

| Wires | PLONK gates | FFT domain | Test SRS | Preprocessing | Proof generation | Peak RSS | Groth16 proof generation (same wires) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 711,041 | 2^20 | 12.3 s | 1.8 s | 8.5 s | 2.1 GiB | 0.5 s |
| 8 | 2,011,165 | 2^21 | 24.1 s | 3.8 s | 16.9 s | 3.7 GiB | 1.9 s |
| 32 | 6,468,733 | 2^23 | 97.4 s | 13.3 s | 69.0 s | 14.4 GiB | 5.0 s |
| 64 | 12,412,157 | 2^24 | 199.3 s | 23.6 s | 129.0 s | 24.1 GiB | — |

Compile-only gate counts at 1, 2, 4, 8 and 32 wires are in `compile/`: 92,866 gates per row against 26,810 R1CS constraints for Groth16.

Limits: gnark's PLONK prover works on a domain four times the circuit size, and BN254 supports FFT domains up to 2^28, so one proof holds at most 2^26 ≈ 67M gates, about 358 wires. The full 1,019-wire circuit (about 190M gates) needs at least three proofs. Aztec Ignition's 100.8M-point SRS covers domains up to 2^26.
