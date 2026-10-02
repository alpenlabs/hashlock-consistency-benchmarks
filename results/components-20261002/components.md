# Component costs, amortized per operation

Apple M2 Max, 12 threads, one trial per size. SP1 rows: (N = 1000 run − N = 0 run) / 1000, core and compressed proofs (Groth16 wrapping is a fixed ~147 s and excluded). gnark rows: (larger-N run − N = 1 run) / (N − 1), Groth16 over BN254 with gnark v0.14.0. All outputs were checked against independent native implementations; all proofs verified.

## SP1 (zkVM)

| Operation | Cycles per op | Precompile calls per op | Proving per op (core + compress) | Fixed cost at N = 0 |
| --- | ---: | --- | ---: | ---: |
| No-op (decode 32-byte input, fold) | 321 | — | 5.44 ms (5.52 + -0.08) | 5,861 cycles, 10.7 s |
| SHA-256, precompile | 959 | 1 sha_compress, 1 sha_extend | 50.79 ms (23.49 + 27.31) | 5,844 cycles, 10.8 s |
| SHA-256, software | 4,729 | — | 102.62 ms (75.42 + 27.20) | 5,845 cycles, 10.6 s |
| 128-bit XOR | 280 | — | 5.44 ms (5.42 + 0.01) | 5,776 cycles, 10.8 s |
| BN254 field mul (uint256_mul) | 295 | 1 uint256_mul | 25.95 ms (7.59 + 18.36) | 5,942 cycles, 10.7 s |
| Baby Jubjub fixed-base mul | 38,750 | 229 uint256_mul | 1,622.77 ms (956.05 + 666.71) | 15,778,057 cycles, 883.7 s |
| secp256k1 fixed-base mul | 2,843 | 30.873 secp256k1_add | 332.99 ms (104.81 + 228.18) | 1,848,761 cycles, 158.8 s |
| Commit 32 public bytes | 2,355 | — | 54.45 ms (36.33 + 18.12) | 5,648 cycles, 10.7 s |

Cycles per op include decoding one 32-byte input and folding the result into the output (the no-op row). Fixed costs include program start, the precomputed point tables for the two curve rows, and the minimum shard set.

## gnark (native Groth16)

| Operation | N | Constraints per op | Key generation per op | Proof generation per op |
| --- | ---: | ---: | ---: | ---: |
| BN254 field mul (native) | 1,000 | 1 | 0.06 ms | 0.008 ms |
| 128-bit XOR | 1,000 | 81 | 7.91 ms | 0.328 ms |
| Baby Jubjub fixed-base mul | 1,000 | 1,308 | 36.67 ms | 2.546 ms |
| SHA-256 | 200 | 25,502 | 1,936.30 ms | 77.837 ms |
| secp256k1 fixed-base mul | 100 | 44,605 | 3,420.05 ms | 139.237 ms |

Fixed constraints (lookup tables) are excluded from the per-op figures: about 131.8K for SHA-256 and 65.8K for the byte XOR. SHA-256 and secp256k1 used N = 200 and N = 100 because 1,000 repetitions would be a 25–55M-constraint circuit, beyond this machine's memory at Groth16 key generation.

## Sanity check: full-size runs rebuilt from components

| Run | Quantity | From components | Measured | Ratio |
| --- | --- | ---: | ---: | ---: |
| Hashlock, gnark, 2,038 rows | constraints | 54,769,885 | 54,769,883 | 1.00 |
| Hashlock, gnark, 1,024 rows (512 wires) | proof generation, s | 82.3 | 73.0 | 1.13 |
| Hashlock, SP1, secp256k1 | guest cycles | 21,376,989 | 20,754,976 | 1.03 |
| Hashlock, SP1, secp256k1 | core + compress, s | 1,274 | 1,254 | 1.02 |
| Hashlock, SP1, Baby Jubjub | guest cycles | 108,484,007 | 107,886,049 | 1.01 |
| Hashlock, SP1, Baby Jubjub | core + compress, s | 4,627 | 4,499 | 1.03 |
| Soldering, M = 7 | guest cycles | 60,077,085 | 55,972,409 | 1.07 |
| Soldering, M = 7 | core + compress, s | 2,126 | 1,645 | 1.29 |

Reconstructions add per-op costs linearly. SP1's recursion cost depends on how events fall into shards, so the time reconstructions are approximate; cycle reconstructions should be close. The soldering cycle estimate counts one input decode per label pair (7 × 2,038), the 16,304 label hashes, the 12,228 XORs and the 717,520 public bytes.
