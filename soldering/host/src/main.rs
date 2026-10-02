use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use p3_field::PrimeField32;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1Prover, SP1PublicValues, components::CpuProverComponents};
use sp1_stark::{SP1ProverOpts, Word, air::PublicValues};

// Build the upstream guest source unchanged; share its input/output schema.
#[path = "../../guest/src/types.rs"]
mod types;
use types::{SolderedLabelsData, WiresInput};

const ELF: &[u8] = include_bytes!(env!("SP1_ELF_sp1-soldering-guest"));
const UPSTREAM: &str = "52b49127dc426f0c88ce7fc418116e67173c2f22";

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

fn hash_label(label: u128) -> [u8; 32] {
    Sha256::digest(label.to_be_bytes()).into()
}

fn input(wires: usize, instances: usize, seed: u64) -> WiresInput {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let nonce = rng.r#gen();
    let instances_wires = (0..instances)
        .map(|_| {
            let offset = rng.r#gen::<u128>() | 1;
            (0..wires)
                .map(|_| {
                    let zero = rng.r#gen::<u128>();
                    (zero, zero ^ offset)
                })
                .collect()
        })
        .collect();
    WiresInput {
        instances_wires,
        nonce,
    }
}

// Independent host oracle: iterate per replica, unlike the guest's per-wire loop.
fn expected(input: &WiresInput) -> SolderedLabelsData {
    let (base, rest) = input.instances_wires.split_first().unwrap();
    SolderedLabelsData {
        base_commitment: base
            .iter()
            .map(|&(a, b)| (hash_label(a), hash_label(b)))
            .collect(),
        base_nonce_commitment: base
            .iter()
            .map(|&(a, b)| (hash_label(a ^ input.nonce), hash_label(b ^ input.nonce)))
            .collect(),
        commitments: rest
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|&(a, b)| (hash_label(a), hash_label(b)))
                    .collect()
            })
            .collect(),
        deltas: rest
            .iter()
            .map(|instance| {
                base.iter()
                    .zip(instance.iter())
                    .map(|(&(a, b), &(c, d))| (a ^ c, b ^ d))
                    .collect()
            })
            .collect(),
        nonce: input.nonce,
    }
}

fn check_translation(input: &WiresInput, output: &SolderedLabelsData) {
    for (i, instance) in input.instances_wires.iter().enumerate().skip(1) {
        for (j, &(a, b)) in instance.iter().enumerate() {
            let (base0, base1) = input.instances_wires[0][j];
            let (d0, d1) = output.deltas[i - 1][j];
            assert_eq!(base0 ^ d0, a);
            assert_eq!(base1 ^ d1, b);
        }
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
                "soldering-bench --mode execute|core|compressed|groth16 --wires N --instances M --out DIR [--seed 20261001] [--artifacts DIR]"
            );
            return;
        }
        assert!(
            [
                "--mode",
                "--wires",
                "--instances",
                "--out",
                "--seed",
                "--artifacts"
            ]
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
    let wires: usize = flags
        .get("--wires")
        .expect("--wires required")
        .parse()
        .unwrap();
    let instances: usize = flags
        .get("--instances")
        .expect("--instances required")
        .parse()
        .unwrap();
    let seed: u64 = flags
        .get("--seed")
        .map(String::as_str)
        .unwrap_or("20261001")
        .parse()
        .unwrap();
    assert!(
        wires > 0 && instances >= 2,
        "need positive wires and at least two total instances"
    );
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
        "wires": wires, "total_retained_instances": instances,
        "additional_instances": instances - 1, "seed": seed,
        "label_bytes": 16, "input_distribution": "independent odd Free-XOR offset per instance",
        "upstream_commit": UPSTREAM, "sp1_crates_version": "5.2.2",
        "sp1_circuit_version": sp1_prover::SP1_CIRCUIT_VERSION.trim(),
        "guest_elf_sha256": hex(&Sha256::digest(ELF)),
        "host_arch": std::env::consts::ARCH, "host_os": std::env::consts::OS,
        "environment": {}, "timings_s": {}, "verified_stages": [],
        "proof_bytes": {}, "note": "One local trial; not an exact reproduction of BABE's table."
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
    let (input, input_bytes, oracle_bytes) = stage(&out, &mut record, "input_and_oracle", || {
        let input = input(wires, instances, seed);
        let oracle = expected(&input);
        check_translation(&input, &oracle);
        let config = bincode::config::standard().with_fixed_int_encoding();
        let input_bytes = bincode::encode_to_vec(&input, config).unwrap();
        let oracle_bytes = bincode::encode_to_vec(&oracle, config).unwrap();
        (input, input_bytes, oracle_bytes)
    });
    record["input_bytes"] = json!(input_bytes.len());
    record["input_sha256"] = json!(hex(&Sha256::digest(&input_bytes)));
    record["public_values_bytes"] = json!(oracle_bytes.len());
    record["expected_sha256_label_hashes"] = json!(2 * wires * (instances + 1));
    record["expected_xor_label_bindings"] = json!(2 * wires * (instances - 1));
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
    let (actual, consumed): (SolderedLabelsData, usize) = bincode::decode_from_slice(
        public_values.as_slice(),
        bincode::config::standard().with_fixed_int_encoding(),
    )
    .unwrap();
    assert_eq!(consumed, public_values.as_slice().len());
    check_translation(&input, &actual);
    record["guest_instructions"] = json!(report.total_instruction_count());
    record["guest_syscalls"] = json!(report.total_syscall_count());
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
