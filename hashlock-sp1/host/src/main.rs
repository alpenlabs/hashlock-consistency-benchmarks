use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use k256::{
    ProjectivePoint, Scalar, U256,
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
};
use num_bigint::BigUint;
use p3_field::PrimeField32;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1Prover, SP1PublicValues, components::CpuProverComponents};
use sp1_stark::{SP1ProverOpts, Word, air::PublicValues};

// Shares the guest's input schema and output layout.
#[path = "../../guest/src/types.rs"]
mod types;
use types::{CURVE_BABYJUBJUB, CURVE_SECP256K1, HEADER_BYTES, HashlockInput, ROW_BYTES};

const ELF: &[u8] = include_bytes!(env!("SP1_ELF_hashlock-sp1-guest"));
// Baby Jubjub prime-subgroup order L, big-endian; fixtures are sampled below it as in circuit/witness.go.
const ORDER_BE: [u8; 32] = [
    0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
    0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn save(out: &Path, record: &Value) {
    let tmp = out.join("result.json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(record).unwrap()).unwrap();
    fs::rename(tmp, out.join("result.json")).unwrap();
}

fn stage<T>(out: &Path, record: &mut Value, name: &str, f: impl FnOnce() -> T) -> T {
    record["active_stage"] = json!(name);
    save(out, record);
    eprintln!("stage={name} status=started");
    let t = Instant::now();
    let value = f();
    let seconds = t.elapsed().as_secs_f64();
    record["timings_s"][name] = json!(seconds);
    save(out, record);
    eprintln!("stage={name} status=finished seconds={seconds:.6}");
    value
}

/// Mirrors sample() in circuit/witness.go byte for byte, so both benchmarks prove the same rows.
fn sample(seed: &str, row: u64) -> [u8; 32] {
    for counter in 0u64.. {
        let mut h = Sha256::new();
        h.update(b"hashlock-consistency-bench/v1\x00");
        h.update((seed.len() as u64).to_be_bytes());
        h.update(seed.as_bytes());
        h.update(row.to_be_bytes());
        h.update(counter.to_be_bytes());
        let mut candidate: [u8; 32] = h.finalize().into();
        candidate[0] &= 0x07; // 251 bits; reject rather than reduce modulo the order.
        if candidate < ORDER_BE {
            return candidate;
        }
    }
    unreachable!()
}

fn be32(decimal: &str) -> [u8; 32] {
    let bytes = BigUint::parse_bytes(decimal.as_bytes(), 10)
        .expect("decimal coordinate")
        .to_bytes_be();
    assert!(bytes.len() <= 32, "coordinate exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Independent oracle: Baby Jubjub points from gnark-crypto via cmd/statement,
/// secp256k1 points from the k256 crate, digests from the host sha2 crate.
fn expected(curve: u8, preimages: &[[u8; 32]], statement: Option<&Path>) -> Vec<u8> {
    let gnark: Option<Vec<Value>> =
        statement.map(|p| serde_json::from_slice(&fs::read(p).expect("read statement")).unwrap());
    if curve == CURVE_BABYJUBJUB {
        let rows = gnark.as_ref().expect("--statement is required for babyjubjub");
        assert_eq!(rows.len(), preimages.len(), "statement row count differs");
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + preimages.len() * ROW_BYTES);
    out.push(curve);
    out.extend_from_slice(&(preimages.len() as u32).to_le_bytes());
    for (r, preimage) in preimages.iter().enumerate() {
        let digest: [u8; 32] = Sha256::digest(preimage).into();
        out.extend_from_slice(&digest);
        if curve == CURVE_BABYJUBJUB {
            let row = &gnark.as_ref().unwrap()[r];
            assert_eq!(row["wire"], json!(r / 2), "statement wire order");
            assert_eq!(row["value"], json!(r % 2), "statement value order");
            // Matching digests also confirm that this fixture equals the Go fixture.
            assert_eq!(row["sha256"].as_str().unwrap(), hex(&digest), "fixture differs from gnark statement");
            out.extend_from_slice(&be32(row["point_x"].as_str().unwrap()));
            out.extend_from_slice(&be32(row["point_y"].as_str().unwrap()));
        } else {
            let scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(preimage));
            let point = (ProjectivePoint::GENERATOR * scalar).to_affine().to_encoded_point(false);
            out.extend_from_slice(point.x().unwrap());
            out.extend_from_slice(point.y().unwrap());
        }
    }
    out
}

fn main() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let mut flags = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        if key == "--help" {
            println!(
                "hashlock-sp1-bench --mode execute|core|compressed|groth16 --curve babyjubjub|secp256k1 --wires N --out DIR [--seed 20261001] [--statement FILE] [--artifacts DIR]"
            );
            return;
        }
        assert!(
            ["--mode", "--curve", "--wires", "--out", "--seed", "--statement", "--artifacts"]
                .contains(&key.as_str()),
            "unknown option: {key}"
        );
        let value = args.next().expect("option requires a value");
        assert!(flags.insert(key, value).is_none(), "duplicate option");
    }
    let mode = flags.get("--mode").map(String::as_str).unwrap_or("execute");
    assert!(
        ["execute", "core", "compressed", "groth16"].contains(&mode),
        "invalid mode"
    );
    let curve_name = flags.get("--curve").map(String::as_str).expect("--curve required");
    let curve = match curve_name {
        "babyjubjub" => CURVE_BABYJUBJUB,
        "secp256k1" => CURVE_SECP256K1,
        _ => panic!("invalid curve"),
    };
    let wires: usize = flags
        .get("--wires")
        .expect("--wires required")
        .parse()
        .unwrap();
    assert!(wires > 0, "need positive wires");
    let seed = flags.get("--seed").cloned().unwrap_or_else(|| "20261001".into());
    let statement = flags.get("--statement").map(PathBuf::from);
    let out = PathBuf::from(flags.get("--out").expect("--out required"));
    assert!(
        !out.exists(),
        "output directory already exists; use a new path"
    );
    let artifacts = flags.get("--artifacts").map(PathBuf::from);
    if mode == "groth16" {
        let path = artifacts
            .as_ref()
            .expect("--artifacts required for groth16; no implicit download");
        assert!(path.is_dir(), "Groth16 artifacts directory does not exist");
        // Reject Groth16 artifacts from another SP1 version before proving.
        let version = sp1_prover::SP1_CIRCUIT_VERSION.trim();
        assert!(
            path.file_name().and_then(|n| n.to_str()) == Some(version),
            "Groth16 artifacts directory must be named {version} for this SP1 build"
        );
        for file in ["groth16_pk.bin", "groth16_circuit.bin", "groth16_vk.bin"] {
            assert!(path.join(file).is_file(), "missing Groth16 artifact {file}");
        }
    }
    // Benchmark real CPU proving only. Do not silently accept mock/development modes.
    assert!(
        std::env::var("SP1_DEV_MODE").is_err(),
        "unset SP1_DEV_MODE for this benchmark"
    );
    assert!(
        std::env::var("SP1_PROVER").map_or(true, |v| v == "cpu"),
        "CPU backend required"
    );
    fs::create_dir_all(&out).unwrap();
    let mut record = json!({
        "schema_version": 2, "status": "running", "mode": mode,
        "approach": "hashlock-sp1", "curve": curve_name,
        "wires": wires, "rows_per_wire": 2, "rows": 2 * wires, "seed": seed,
        "preimage_bytes": 32, "scalar_encoding": "unsigned 32-byte big-endian; no y < L condition",
        "fixed_base_method": "8-bit windows, 32 x 256 table computed in the guest",
        "sp1_crates_version": "5.2.2",
        "sp1_circuit_version": sp1_prover::SP1_CIRCUIT_VERSION.trim(),
        "guest_elf_sha256": hex(&Sha256::digest(ELF)),
        "host_arch": std::env::consts::ARCH, "host_os": std::env::consts::OS,
        "environment": {}, "timings_s": {}, "verified_stages": [],
        "proof_bytes": {}, "note": "One local trial."
    });
    if mode == "groth16" {
        let path = artifacts.as_ref().unwrap();
        record["groth16_artifacts"] = json!(path.display().to_string());
        record["groth16_vk_sha256"] =
            json!(hex(&Sha256::digest(fs::read(path.join("groth16_vk.bin")).unwrap())));
    }
    for name in [
        "RAYON_NUM_THREADS",
        "GOMAXPROCS",
        "SHARD_SIZE",
        "SHARD_BATCH_SIZE",
        "TRACE_GEN_WORKERS",
        "SPLIT_THRESHOLD",
        "SP1_DISABLE_VK_VERIFICATION",
    ] {
        record["environment"][name] = json!(std::env::var(name).ok());
    }
    assert!(
        std::env::var("SP1_DISABLE_VK_VERIFICATION").is_err(),
        "verification must remain enabled"
    );
    let (input_bytes, oracle_bytes) = stage(&out, &mut record, "input_and_oracle", || {
        let preimages: Vec<[u8; 32]> = (0..2 * wires as u64).map(|r| sample(&seed, r)).collect();
        let oracle = expected(curve, &preimages, statement.as_deref());
        let input = HashlockInput { curve, preimages };
        let config = bincode::config::standard().with_fixed_int_encoding();
        (bincode::encode_to_vec(&input, config).unwrap(), oracle)
    });
    record["input_bytes"] = json!(input_bytes.len());
    record["input_sha256"] = json!(hex(&Sha256::digest(&input_bytes)));
    record["public_values_bytes"] = json!(oracle_bytes.len());
    record["expected_sha256_evaluations"] = json!(2 * wires);
    record["expected_fixed_base_scalar_multiplications"] = json!(2 * wires);
    if let Some(path) = &statement {
        record["statement_sha256"] = json!(hex(&Sha256::digest(fs::read(path).unwrap())));
    }
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input_bytes);
    let prover = stage(&out, &mut record, "prover_initialization", || {
        SP1Prover::<CpuProverComponents>::new()
    });
    assert!(
        prover.vk_verification,
        "SP1 recursion verification disabled"
    );
    let (public_values, _, report) = stage(&out, &mut record, "execute", || {
        prover
            .execute(ELF, &stdin, SP1ContextBuilder::default().build())
            .expect("guest execution failed")
    });
    assert_eq!(
        public_values.as_slice(),
        oracle_bytes.as_slice(),
        "guest output differs from host oracle"
    );
    record["guest_instructions"] = json!(report.total_instruction_count());
    record["guest_syscalls"] = json!(report.total_syscall_count());
    record["cycle_tracker"] = json!(report.cycle_tracker);
    record["guest_output_matches_host"] = json!(true);
    fs::write(out.join("execution-report.txt"), report.to_string()).unwrap();
    fs::write(out.join("public-values.bin"), &oracle_bytes).unwrap();
    let mut expected_bad = oracle_bytes.clone();
    expected_bad[0] ^= 1;
    assert_ne!(Sha256::digest(&expected_bad), Sha256::digest(&oracle_bytes));
    if mode != "execute" {
        let opts = SP1ProverOpts::default();
        record["prover_options"] = serde_json::to_value(opts).unwrap();
        let (_pk, pk_device, program, vk) =
            stage(&out, &mut record, "key_setup", || prover.setup(ELF));
        let core = stage(&out, &mut record, "core_prove", || {
            prover
                .prove_core(
                    &pk_device,
                    program,
                    &stdin,
                    opts,
                    SP1ContextBuilder::default().build(),
                )
                .expect("core proving failed")
        });
        record["core_cycles"] = json!(core.cycles);
        record["core_shards"] = json!(core.proof.0.len());
        assert_eq!(core.public_values.as_slice(), oracle_bytes.as_slice());
        stage(&out, &mut record, "core_verify", || {
            prover
                .verify(&core.proof, &vk)
                .expect("core verification failed");
            let pv: &PublicValues<Word<_>, _> = core
                .proof
                .0
                .last()
                .unwrap()
                .public_values
                .as_slice()
                .borrow();
            let committed: Vec<u8> = pv
                .committed_value_digest
                .iter()
                .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
                .collect();
            assert_eq!(
                committed.as_slice(),
                Sha256::digest(&oracle_bytes).as_slice(),
                "proof does not bind expected output"
            );
            assert_ne!(
                committed.as_slice(),
                Sha256::digest(&expected_bad).as_slice(),
                "changed output must not match proof"
            );
        });
        record["verified_stages"]
            .as_array_mut()
            .unwrap()
            .push(json!("core"));
        record["tampered_public_output_rejected"] = json!(true);
        let encoded = bincode1::serialize(&core.proof).unwrap();
        record["proof_bytes"]["core"] = json!(encoded.len());
        fs::write(out.join("core.proof.bin"), encoded).unwrap();
        if mode != "core" {
            let compressed = stage(&out, &mut record, "compress", || {
                prover
                    .compress(&vk, core, vec![], opts)
                    .expect("compression failed")
            });
            stage(&out, &mut record, "compressed_verify", || {
                prover
                    .verify_compressed(&compressed, &vk)
                    .expect("compressed verification failed")
            });
            record["verified_stages"]
                .as_array_mut()
                .unwrap()
                .push(json!("compressed"));
            let encoded = bincode1::serialize(&compressed).unwrap();
            record["proof_bytes"]["compressed"] = json!(encoded.len());
            fs::write(out.join("compressed.proof.bin"), encoded).unwrap();
            if mode == "groth16" {
                let shrunk = stage(&out, &mut record, "shrink", || {
                    prover.shrink(compressed, opts).expect("shrink failed")
                });
                stage(&out, &mut record, "shrink_verify", || {
                    prover
                        .verify_shrink(&shrunk, &vk)
                        .expect("shrink verification failed")
                });
                let wrapped = stage(&out, &mut record, "wrap_bn254", || {
                    prover.wrap_bn254(shrunk, opts).expect("BN254 wrap failed")
                });
                stage(&out, &mut record, "wrap_bn254_verify", || {
                    prover
                        .verify_wrap_bn254(&wrapped, &vk)
                        .expect("BN254 verification failed")
                });
                let proof = stage(&out, &mut record, "groth16_wrap", || {
                    prover.wrap_groth16_bn254(wrapped, artifacts.as_ref().unwrap())
                });
                stage(&out, &mut record, "groth16_verify", || {
                    prover
                        .verify_groth16_bn254(
                            &proof,
                            &vk,
                            &SP1PublicValues::from(oracle_bytes.as_slice()),
                            artifacts.as_ref().unwrap(),
                        )
                        .expect("Groth16 verification failed");
                });
                // Keep one successful verification separate from the negative test.
                stage(&out, &mut record, "groth16_negative_verify", || {
                    assert!(
                        prover
                            .verify_groth16_bn254(
                                &proof,
                                &vk,
                                &SP1PublicValues::from(expected_bad.as_slice()),
                                artifacts.as_ref().unwrap()
                            )
                            .is_err()
                    );
                });
                record["groth16_tampered_public_output_rejected"] = json!(true);
                record["verified_stages"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("groth16"));
                let encoded = bincode1::serialize(&proof).unwrap();
                record["proof_bytes"]["groth16_serialized"] = json!(encoded.len());
                fs::write(out.join("groth16.proof.bin"), encoded).unwrap();
                fs::write(
                    out.join("groth16.proof.json"),
                    serde_json::to_vec_pretty(&proof).unwrap(),
                )
                .unwrap();
            }
        }
    }
    let prove_stages = [
        "core_prove",
        "compress",
        "shrink",
        "wrap_bn254",
        "groth16_wrap",
    ];
    let total: f64 = prove_stages
        .iter()
        .filter_map(|k| record["timings_s"][k].as_f64())
        .sum();
    if mode != "execute" {
        record["proof_generation_s_excluding_setup_and_verification"] = json!(total);
    }
    record["status"] = json!("complete");
    record["active_stage"] = Value::Null;
    save(&out, &record);
    println!("{}", serde_json::to_string(&record).unwrap());
}
