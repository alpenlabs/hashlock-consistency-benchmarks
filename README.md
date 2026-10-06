# Soldering and hashlock-consistency proof benchmarks

Two ways to tie garbled-circuit input labels to on-chain data, benchmarked at 1,019 input wires:

- **Soldering** ([BitVM PR #75](https://github.com/BitVM/garbled-snark-verifier/pull/75), as measured in [BABE](https://eprint.iacr.org/2026/065) §9.3): an SP1 proof that the XOR deltas between a base instance's labels and the other retained instances' labels match their SHA-256 commitments. Cost grows with the number of retained instances M.
- **Hashlock consistency**: one proof that each of the 2,038 wire/value rows satisfies h = SHA256(y) and P = [y]G for a private 32-byte y. Cost depends only on the number of rows.

| # | Version | Prover | Code |
| --- | --- | --- | --- |
| 1 | Soldering, M = 7 | SP1 5.2.2 → Groth16 | `soldering/` (upstream guest, unchanged) |
| 2 | Hashlock, Baby Jubjub | gnark 0.14.0 Groth16 over BN254 | `circuit/`, `cmd/bench` |
| 3 | Hashlock, Baby Jubjub | SP1 5.2.2 → Groth16 | `hashlock-sp1/` |
| 4 | Hashlock, secp256k1 | SP1 5.2.2 → Groth16 | `hashlock-sp1/` (`--curve secp256k1`) |

## Results

Apple M2 Max (12 cores, 64 GB), 12 threads, one trial each. Full tables and raw results: [`results/full-20261002/comparison.md`](results/full-20261002/comparison.md).

| # | Version | Guest cycles / constraints | One-time setup | Proof generation | Peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Soldering, M = 7 | 56.0M cycles | 0.25 s | 1,797 s | 25.7 GiB |
| 2 | Hashlock, gnark | 54.8M constraints | ~3,841 s (est.) | ~145 s (est.) | ~74 GiB (est.) |
| 3 | Hashlock, SP1, Baby Jubjub | 107.9M cycles | 0.27 s | 4,652 s | 26.3 GiB |
| 4 | Hashlock, SP1, secp256k1 | 20.8M cycles | 0.26 s | 1,406 s | 29.6 GiB |

Rows 1, 3 and 4 are full runs whose Groth16 proofs verified. SP1 proof generation is STARK proving plus about 147 s of Groth16 wrapping; its one-time setup is program-key generation, since the Groth16 keys are SP1's pre-made v5.0.0 artifacts. Row 2 does not fit in 64 GB (compiling the full circuit alone peaks at 44 GiB), so it is extrapolated linearly from verified 256- and 512-wire runs; its one-time setup is circuit-specific Groth16 key generation.

## Soldering against BABE

BABE's Table 4 reports SP1 soldering times for the same 1,019-label configuration. Our runs use the same harness and settings as row 1 above; all Groth16 proofs verified.

| M | SHA-256 label hashes | Guest cycles | STARK proving | Proof generation (incl. Groth16 wrap) | BABE Table 4 | Ours / BABE |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 12,228 | 40.9M | 1,266 s | 1,415 s | 1,529 s | 0.93 |
| 6 | 14,266 | 48.4M | 1,460 s | 1,614 s | 1,740 s | 0.93 |
| 7 | 16,304 | 56.0M | 1,650 s | 1,797 s | 1,977 s | 0.91 |

The hardware differs, so this is a consistency check, not a reproduction:

| | This repo | BABE |
| --- | --- | --- |
| CPU | Apple M2 Max, 12 cores | AMD Ryzen 7 7840U, 16 CPU threads |
| RAM | 64 GB | not stated |
| Threads | 12 | not stated |
| SP1 | 5.2.2 (CPU prover, v5.0.0 Groth16 artifacts) | not stated |
| What is timed | each stage separately; both columns shown | "time to generate a zk-SNARK proof" (stages not stated) |

SP1 sizes shards by installed RAM, so a machine with different memory also proves with different shard settings. Each extra instance adds about 190 s here and 210–240 s in BABE's table.

## Hashlock with PLONK

PLONK avoids Groth16's circuit-specific trusted setup by using a universal KZG reference string, such as [Aztec Ignition](https://github.com/AztecProtocol/ignition-verification) (transcripts at `https://aztec-ignition.s3.amazonaws.com/`, loadable with [gnark-ignition-verifier](https://pkg.go.dev/github.com/consensys/gnark-ignition-verifier)). The same circuit, built with `-backend plonk`, measured at small sizes ([`results/plonk-20261002/`](results/plonk-20261002/README.md)):

| | Groth16 | PLONK |
| --- | ---: | ---: |
| Size per row | 26,810 constraints | 92,866 gates |
| Proof generation, 32 wires | 5.0 s | 69.0 s |
| Peak RSS, 32 wires | 4.1 GiB | 14.4 GiB |
| Proof size | 196 B | 584 B |

One gnark PLONK proof on BN254 holds at most about 358 wires (the prover's FFT domain is 4× the circuit size, and BN254 caps domains at 2^28), so 1,019 wires need at least three proofs; memory limits this machine to about 177 wires per proof. Estimated total proof generation is 33–37 minutes, slower than the single SP1 secp256k1 proof (23.4 min), which also needs no circuit-specific setup.

## Component costs

[`components/`](components/README.md) measures single operations, repeated up to 1,000 times, and reports the amortized cost of one:

| Operation | SP1 proving | gnark proof generation | gnark constraints |
| --- | ---: | ---: | ---: |
| SHA-256 (precompile in SP1) | 50.8 ms | 77.8 ms | 25,502 |
| SHA-256, software (SP1) | 102.6 ms | — | — |
| Baby Jubjub fixed-base multiplication | 1,622.8 ms | 2.5 ms | 1,308 |
| secp256k1 fixed-base multiplication | 333.0 ms | 139.2 ms (emulated) | 44,605 |
| 128-bit XOR | ≈ 0 | 0.33 ms | 81 |
| Commit 32 public bytes (SP1) | 54.5 ms | — | — |

SP1 figures exclude Groth16 wrapping. Summed, the components reproduce the full-size cycle and constraint counts within 1–7%. Ideas for speeding things up are in [docs/optimizations.md](docs/optimizations.md); [experiments/public-values](experiments/public-values/README.md) tests one of them.

## Running

Requires Go 1.24+, Rust 1.90, Python 3.9+, the SP1 `succinct` toolchain, and SP1's Groth16 artifacts in `~/.sp1/circuits/groth16/v5.0.0` (see [soldering/README.md](soldering/README.md)).

```sh
# Build
go build -o bin/hashlock-bench ./cmd/bench
go build -o bin/hashlock-statement ./cmd/statement
cargo build --locked --release --manifest-path soldering/host/Cargo.toml
cargo build --locked --release --manifest-path hashlock-sp1/host/Cargo.toml

# Full-size cases (hours; run detached), then tables
python3 scripts/full_runs.py --out results/<dir> --cases soldering-m7 hashlock-sp1-secp256k1 ...
python3 scripts/build_tables.py results/<dir>

# Soldering against the gnark hashlock circuit with one runner (--dry-run to preview)
python3 run.py --wires 1019 --instances 7 --threads 12

# Tests
python3 -m unittest discover -s tests
go test ./...
```

The Baby Jubjub SP1 case needs the gnark-crypto statement as its oracle: `bin/hashlock-statement -wires 1019 -out results/hashlock-sp1-statements/w1019.json`.

## Layout

```text
circuit/                 gnark hashlock circuit and tests (relation details: docs/hashlock.md)
cmd/bench, cmd/verify    gnark prover (compile, setup, prove; -keys for separate processes; -backend plonk) and verifier
cmd/statement            writes the public statement with gnark-crypto
soldering/               upstream SP1 soldering guest and benchmark host
hashlock-sp1/            hashlock relation as an SP1 guest, and its host
components/              per-operation benchmarks for SP1 and gnark
experiments/             soldering guest variants for public-value hashing
scripts/                 full-size driver and table builder
run.py, tests/           two-approach runner and its tests
results/                 measured results
```
