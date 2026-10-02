# Optimization ideas

None of these is applied to the reported results. Figures are measured unless marked otherwise.

## All SP1 guests

**Hash public values with the precompile.** `sp1-zkvm` 5.2.2 hashes committed public values with its crates.io `sha2` dependency, in software (about 55–60 cycles per byte). A `[patch.crates-io]` entry pointing `sha2` at the SP1-patched crate moves this onto the SHA-256 precompile without changing the digest. For soldering at 1,019 wires this cuts guest cycles from 56.0M to 16.2M; core plus compressed proving falls 31–38% at 128 and 256 wires ([experiments/public-values](../experiments/public-values/README.md)).

**A digest alone does not help.** An SP1 proof exposes only a digest of the public values, computed inside the guest, so every public byte is hashed in the guest however it is committed. Committing a guest-computed digest instead of the data saves nothing unless that digest uses the precompile. Native Groth16 differs: public inputs enter the verifier directly, with no in-circuit hashing.

**Fewer shards.** Compression cost tracks shard count, and precompile events get their own shards: secp256k1 hashlock had 39 shards and 719 s of compression for 20.8M cycles, Baby Jubjub 210 shards and 1,849 s. SP1 divides its precompile split thresholds by 8 on a 49–64 GB machine and by 2 above 64 GB, so more RAM, explicit `SP1ProverOpts`, or fewer precompile calls all reduce the work.

## Hashlock in SP1

**Build-time point table.** The Baby Jubjub guest builds its 32 × 256 table at run time (15.7M cycles, about 132K field multiplications, 884 s of proving); generating it in `build.rs` would make it static data.

**Cheaper field arithmetic.** About 167 guest instructions surround each `uint256_mulmod` call (operand copies, fully reduced add/sub); lazy reduction and fewer copies would cut these.

**Batch the group check.** With Fiat–Shamir weights ρ_r over all (h_r, P_r), prove [Σ ρ_r y_r mod L]G and let the verifier compare it with Σ ρ_r P_r: one multiplication instead of 2,038. This is a protocol change; soundness relies on each h_r fixing y_r before ρ is derived.

**Group choice.** In a zkVM, Baby Jubjub loses its advantage: 107.9M cycles against 20.8M for secp256k1 with the curve precompile. BN254 G1 and ed25519 also have SP1 precompiles (untested).

## Hashlock in gnark

**SHA-256 dominates.** 25,502 of each row's 26,810 constraints are SHA-256; the multiplication is 1,308. Speedups must come from the hash gadget or a proof system with cheaper lookups.

**Duplicated byte check.** Each preimage byte is range-checked by both `api.ToBinary` and `uints.ValueOf`, about 1% of the circuit.

**Memory.** The live heap is about 1.1 KiB per constraint, about 61 GiB at 1,019 wires, so the full circuit needs a machine with more than 64 GB, or GPU proving through gnark's ICICLE backend. This matches reports elsewhere: the old gnark README's 1–2 GB per million constraints ([mirror](https://pkg.go.dev/github.com/philsippl/gnark)), and zkbnb's 128 GB for 60M constraints, which they reduced by lazily expanding repeated sub-circuits ([write-up](https://hackmd.io/@JIJKVPoYSZaHxu42ObOitQ/SJDZWE-Gh)), an approach that fits this circuit's 2,038 identical rows.

## Soldering

**Commit each non-base instance with one hash.** Per-label commitments for the non-base instances (12,228 single-block hashes at M = 7) could become one hash or Merkle root per instance: about 7,100 instead of 16,300 compressions and 326 KB instead of 717 KB of public output. The base instance keeps per-label hashes for its hashlocks. This changes the cut-and-choose commitment format.

**Groth16 wrapping.** The soldering proof is checked off-chain, so the 147 s wrap is not needed for on-chain verification, but it may be what makes the proof zero-knowledge, which it must be because the witness holds every unrevealed label. Check whether SP1's compressed proof hides its witness before dropping the wrap.

**No SNARK at all.** XOR-homomorphic commitments (as in LEGO and DUPLO) solder labels without a proof, at the cost of interaction; verifiable secret sharing (BABE §9.4) is another option. Both change the protocol's communication or trust model.
