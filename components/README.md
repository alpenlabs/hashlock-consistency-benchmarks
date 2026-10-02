# Component benchmarks

Each operation is repeated over N inputs; the amortized cost of one is the difference between two runs divided by the difference in N. Summing the components should reproduce the full-size results.

- **SP1** (`sp1/`): N = 0 and 1,000, core and compressed proofs (Groth16 wrapping, a fixed ~147 s, is excluded). The curve operations are the hashlock guest's code.
- **gnark** (`gnark/`): N = 1 and 1,000, except SHA-256 (200) and secp256k1 (100), whose 1,000-repetition circuits would not fit in memory. The SHA-256 and Baby Jubjub gadgets are the hashlock circuit's.

Every SP1 output is checked against an independent implementation (host `sha2`, `num-bigint`, `k256`, gnark-crypto); every gnark proof is verified and must fail on a changed public input.

The **no-op** decodes one 32-byte input and XORs it into the output. Every SP1 operation does this too, so its cost (321 cycles, 5.4 ms per item) is the input-handling overhead, and its N = 0 cost (5,861 cycles, 10.7 s) is SP1's minimum proof.

```sh
cargo build --locked --release --manifest-path components/sp1/host/Cargo.toml
go build -o bin/components-gnark ./components/gnark
python3 components/run.py --out results/components-<date>/proofs
python3 components/build_table.py results/components-<date>
```

## Results

Apple M2 Max, 12 threads. Full output: [`results/components-20261002/components.md`](../results/components-20261002/components.md).

SP1:

| Operation | Cycles per op | Precompile calls per op | Proving per op | Fixed cost (N = 0) |
| --- | ---: | --- | ---: | ---: |
| No-op | 321 | — | 5.4 ms | 5,861 cycles, 10.7 s |
| SHA-256, precompile | 959 | 1 compress + 1 extend | 50.8 ms | 5,844 cycles, 10.8 s |
| SHA-256, software | 4,729 | — | 102.6 ms | 5,845 cycles, 10.6 s |
| 128-bit XOR | 280 | — | 5.4 ms | 5,776 cycles, 10.8 s |
| BN254 field multiplication | 295 | 1 `uint256_mul` | 26.0 ms | 5,942 cycles, 10.7 s |
| Baby Jubjub fixed-base multiplication | 38,750 | 229 `uint256_mul` | 1,622.8 ms | 15.8M cycles, 883.7 s (table) |
| secp256k1 fixed-base multiplication | 2,843 | 30.9 curve additions | 333.0 ms | 1.85M cycles, 158.8 s (table) |
| Commit 32 public bytes | 2,355 | — | 54.5 ms | 5,648 cycles, 10.7 s |

gnark:

| Operation | Constraints per op | Key generation per op | Proof generation per op |
| --- | ---: | ---: | ---: |
| BN254 field multiplication | 1 | 0.06 ms | 0.008 ms |
| 128-bit XOR | 81 | 7.9 ms | 0.33 ms |
| Baby Jubjub fixed-base multiplication | 1,308 | 36.7 ms | 2.5 ms |
| SHA-256 | 25,502 | 1,936 ms | 77.8 ms |
| secp256k1 fixed-base multiplication (emulated) | 44,605 | 3,420 ms | 139.2 ms |

Full-size runs rebuilt from components:

| Run | Quantity | From components | Measured | Ratio |
| --- | --- | ---: | ---: | ---: |
| Hashlock, gnark | constraints | 54,769,885 | 54,769,883 | 1.00 |
| Hashlock, gnark, 512 wires | proof generation | 82.3 s | 73.0 s | 1.13 |
| Hashlock, SP1, secp256k1 | cycles / core + compress | 21.4M / 1,274 s | 20.8M / 1,254 s | 1.03 / 1.02 |
| Hashlock, SP1, Baby Jubjub | cycles / core + compress | 108.5M / 4,627 s | 107.9M / 4,499 s | 1.01 / 1.03 |
| Soldering, M = 7 | cycles / core + compress | 60.1M / 2,126 s | 56.0M / 1,645 s | 1.07 / 1.29 |

gnark proves at 2–3 µs per constraint, so its costs follow constraint counts; the hashlock circuit is almost all SHA-256. SP1 proves a precompiled SHA-256 faster than gnark, and its larger totals come from curve arithmetic outside a native field, software public-value hashing and fixed costs.
