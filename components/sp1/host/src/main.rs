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

#[path = "../../guest/src/types.rs"]
mod types;
use types::*;

const ELF: &[u8] = include_bytes!(env!("SP1_ELF_components-sp1-guest"));
const OPS: [(&str, u8); 8] = [
    ("noop", OP_NOOP),
    ("sha256-precompile", OP_SHA256_PRECOMPILE),
    ("sha256-software", OP_SHA256_SOFTWARE),
    ("xor128", OP_XOR128),
    ("fr-mul-precompile", OP_FR_MUL_PRECOMPILE),
    ("bjj-fixed-base-mul", OP_BJJ_FIXED_BASE_MUL),
    ("secp256k1-fixed-base-mul", OP_SECP256K1_FIXED_BASE_MUL),
    ("commit-32b", OP_COMMIT_32B),
];
const R_DEC: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

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

/// Same generator as components/gnark (item i = SHA256(domain || len(seed) || seed || i)).
fn items(n: usize, seed: &str) -> Vec<[u8; 32]> {
    (0..n as u64)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"components/v1\x00");
            h.update((seed.len() as u64).to_be_bytes());
            h.update(seed.as_bytes());
            h.update(i.to_be_bytes());
            h.finalize().into()
        })
        .collect()
}

fn fold(items: impl Iterator<Item = [u8; 32]>) -> Vec<u8> {
    let mut acc = [0u8; 32];
    for x in items {
        for i in 0..32 {
            acc[i] ^= x[i];
        }
    }
    acc.to_vec()
}

fn be32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

/// Independent oracles: host sha2, num-bigint, k256, and gnark-crypto for Baby Jubjub.
fn expected(op: u8, items: &[[u8; 32]], bjj_oracle: Option<&str>) -> Vec<u8> {
    match op {
        OP_NOOP => fold(items.iter().copied()),
        OP_SHA256_PRECOMPILE | OP_SHA256_SOFTWARE => fold(items.iter().map(|x| Sha256::digest(x).into())),
        OP_XOR128 => {
            let mut acc = 0u128;
            for x in items {
                acc ^= u128::from_le_bytes(x[..16].try_into().unwrap()) ^ u128::from_le_bytes(x[16..].try_into().unwrap());
            }
            acc.to_le_bytes().to_vec()
        }
        OP_FR_MUL_PRECOMPILE => {
            let r = BigUint::parse_bytes(R_DEC.as_bytes(), 10).unwrap();
            let mut acc = BigUint::from(1u32);
            for x in items {
                acc = acc * BigUint::from_bytes_le(x) % &r;
            }
            let mut out = acc.to_bytes_le();
            out.resize(32, 0);
            out
        }
        OP_BJJ_FIXED_BASE_MUL => {
            let hexed = bjj_oracle.expect("--bjj-oracle is required for bjj-fixed-base-mul");
            (0..hexed.len()).step_by(2).map(|i| u8::from_str_radix(&hexed[i..i + 2], 16).unwrap()).collect()
        }
        OP_SECP256K1_FIXED_BASE_MUL => {
            let points: Vec<([u8; 32], [u8; 32])> = items
                .iter()
                .map(|x| {
                    let s = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(x));
                    let p = (ProjectivePoint::GENERATOR * s).to_affine().to_encoded_point(false);
                    (be32(p.x().unwrap()), be32(p.y().unwrap()))
                })
                .collect();
            let mut out = fold(points.iter().map(|p| p.0));
            out.extend(fold(points.iter().map(|p| p.1)));
            out
        }
        OP_COMMIT_32B => items.concat(),
        _ => unreachable!(),
    }
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
                "components-sp1-bench --op NAME --n N --mode execute|core|compressed|groth16 --out DIR [--seed 20261002] [--bjj-oracle HEX] [--artifacts DIR]"
            );
            return;
        }
        assert!(
            ["--op", "--n", "--mode", "--out", "--seed", "--bjj-oracle", "--artifacts"].contains(&key.as_str()),
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
    let op_name = flags.get("--op").map(String::as_str).expect("--op required");
    let op = OPS.iter().find(|(name, _)| *name == op_name).expect("invalid op").1;
    let n: usize = flags.get("--n").expect("--n required").parse().unwrap();
    let seed = flags.get("--seed").cloned().unwrap_or_else(|| "20261002".into());
    let bjj_oracle = flags.get("--bjj-oracle").cloned();
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
        let version = sp1_prover::SP1_CIRCUIT_VERSION.trim();
        assert!(
            path.file_name().and_then(|n| n.to_str()) == Some(version),
            "Groth16 artifacts directory must be named {version} for this SP1 build"
        );
    }
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
        "schema_version": 1, "status": "running", "mode": mode, "approach": "components-sp1",
        "op": op_name, "n": n, "seed": seed, "sp1_crates_version": "5.2.2",
        "guest_elf_sha256": hex(&Sha256::digest(ELF)),
        "environment": {}, "timings_s": {}, "verified_stages": [], "proof_bytes": {}
    });
    for name in ["RAYON_NUM_THREADS", "GOMAXPROCS", "SHARD_SIZE", "SHARD_BATCH_SIZE"] {
        record["environment"][name] = json!(std::env::var(name).ok());
    }
    assert!(
        std::env::var("SP1_DISABLE_VK_VERIFICATION").is_err(),
        "verification must remain enabled"
    );
    let (input_bytes, oracle_bytes) = stage(&out, &mut record, "input_and_oracle", || {
        let items = items(n, &seed);
        let oracle = expected(op, &items, bjj_oracle.as_deref());
        let input = ComponentInput { op, items };
        let config = bincode::config::standard().with_fixed_int_encoding();
        (bincode::encode_to_vec(&input, config).unwrap(), oracle)
    });
    record["input_bytes"] = json!(input_bytes.len());
    record["public_values_bytes"] = json!(oracle_bytes.len());
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
    if expected_bad.is_empty() {
        expected_bad.push(1);
    } else {
        expected_bad[0] ^= 1;
    }
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
