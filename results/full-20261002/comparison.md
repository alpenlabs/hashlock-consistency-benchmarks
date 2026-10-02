# Full-size comparison at 1,019 wires

All runs: Apple M2 Max (12 cores, 64 GB), 12 threads, one trial each. SP1 5.2.2 with v5.0.0 Groth16 artifacts; gnark v0.14.0.

| # | Version | Work | Guest cycles / constraints | One-time setup | Proof generation | Verification | Peak RSS | Proof |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Soldering (BitVM PR #75), M = 7 | 1019 wires × 7 instances | 55,972,409 cycles | 0.25 s program keys | 1,797 s (30.0 min) | 0.004 s | 25.7 GiB | 1,375 B |
| 2 | Hashlock, gnark (**extrapolated**) | 2038 rows | 54,769,883 constraints | ~3,841 s (64.0 min) key generation | ~145 s (2.4 min) | — | ~73.8 GiB (proof), > 64 GB (keys) | 196 B (constant) |
| 3 | Hashlock, SP1, Baby Jubjub | 2038 rows | 107,886,049 cycles | 0.27 s program keys | 4,652 s (77.5 min) | 0.003 s | 26.3 GiB | 1,376 B |
| 4 | Hashlock, SP1, secp256k1 | 2038 rows | 20,754,976 cycles | 0.26 s program keys | 1,406 s (23.4 min) | 0.003 s | 29.6 GiB | 1,376 B |

SP1 proof generation is STARK proving (core, compress, shrink) plus Groth16 wrapping (BN254 wrap, Groth16 wrap). SP1's Groth16 keys are the pre-made v5.0.0 artifacts, so its one-time cost here is only program-key setup. gnark's one-time cost is circuit-specific Groth16 key generation, which a deployment would run once as a trusted setup. Proof sizes use different serializations (SP1 bincode of its Groth16 proof object; gnark's compressed proof with a BSB22 commitment).

## SP1 stage breakdown

| # | Version | Core | Compress | Shrink | BN254 wrap | Groth16 wrap | STARK proving | Groth16 wrapping | Core shards |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Soldering (BitVM PR #75), M = 7 | 1,121.7 | 523.1 | 5.6 | 126.4 | 20.2 | 1,650.5 | 146.6 | 60 |
| 3 | Hashlock, SP1, Baby Jubjub | 2,650.4 | 1,848.8 | 5.6 | 126.6 | 20.2 | 4,504.7 | 146.8 | 210 |
| 4 | Hashlock, SP1, secp256k1 | 535.0 | 719.0 | 5.6 | 126.4 | 20.2 | 1,259.6 | 146.6 | 39 |

## Soldering against BABE Table 4 (1,019 labels)

| M | SHA-256 label hashes | Cycles | STARK proving | Proof generation (incl. Groth16 wrap) | BABE Table 4 | Ours / BABE |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 12,228 | 40.9M | 1,266 s | 1,415 s | 1,529 s | 0.93 |
| 6 | 14,266 | 48.4M | 1,460 s | 1,614 s | 1,740 s | 0.93 |
| 7 | 16,304 | 56.0M | 1,650 s | 1,797 s | 1,977 s | 0.91 |

Ours: Apple M2 Max (12 cores, 64 GB), 12 threads, SP1 5.2.2. BABE: AMD Ryzen 7 7840U (16 CPU threads; RAM not stated), SP1 version not stated, and the paper does not say which proving stages its timer covers. One trial each.

## Hashlock guest cycle breakdown (millions of instructions)

| # | Version | Table | Scalar mults | SHA-256 | Commit public output | Total guest |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 3 | Hashlock, SP1, Baby Jubjub | 15.74 | 78.09 | 1.89 | 11.78 | 107.89 |
| 4 | Hashlock, SP1, secp256k1 | 1.80 | 4.90 | 1.89 | 11.78 | 20.75 |

## gnark bounded runs (key generation and proof generation in separate processes)

| Wires | Rows | Constraints | Key generation | Key-gen peak RSS | Proving key | Proof generation | Proof peak RSS | Verified |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 2 | 185,389 | 15.3 s | 0.5 GiB | 0.05 GB | 0.47 s | 0.4 GiB | True |
| 256 | 512 | 13,858,323 | 980.3 s | 28.2 GiB | 3.42 GB | 36.73 s | 19.3 GiB | True |
| 512 | 1024 | 27,584,875 | 1,940.3 s | 43.1 GiB | 6.81 GB | 73.02 s | 37.6 GiB | True |

The full 1,019-wire circuit compiles to 54,769,883 constraints (218.7 s, peak RSS 44.2 GiB).

Row 2 extrapolates key-generation time, proof-generation time and proof-generation memory linearly in constraints through the 256- and 512-wire runs. It is an estimate, not a measurement: the FFT domain grows to 2^26 at full size, and a 64 GB machine cannot hold the working set.

The gnark runs used GOMEMLIMIT=44GiB. The 512-wire key generation peaked at the limit, so its memory is not extrapolated; it exceeds 64 GB because compiling the full circuit alone peaked at 44.2 GiB and the 128-wire GC trace puts the live heap at about 1.1 KiB per constraint (about 61 GiB at full size) before the proving key is written out.
