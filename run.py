#!/usr/bin/env python3
"""Compare SP1 soldering and native Groth16 hashlock consistency, sequentially."""
import argparse
import csv
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SP1_PROVE_STAGES = ("core_prove", "compress", "shrink", "wrap_bn254", "groth16_wrap")
ENV_KEYS = ("RAYON_NUM_THREADS", "GOMAXPROCS", "GOGC", "GOMEMLIMIT", "GODEBUG",
            "SHARD_SIZE", "SHARD_BATCH_SIZE", "TRACE_GEN_WORKERS", "SPLIT_THRESHOLD",
            "SP1_PROVER", "SP1_DEV_MODE", "SP1_DISABLE_VK_VERIFICATION")
TABLE_FIELDS = ("trial", "approach", "status", "wires", "retained_instances", "rows",
                "setup_s", "proof_generation_s", "verification_s", "process_wall_s",
                "peak_rss_bytes", "serialized_proof_file_bytes", "error")


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(command):
    try:
        p = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        return {"command": command, "exit_code": p.returncode,
                "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except OSError as exc:
        return {"command": command, "error": str(exc)}


def approaches(args):
    return ["soldering", "hashlock"] if args.approach == "both" else [args.approach]


def binary_path(approach):
    return ROOT / ("soldering/host/target/release/soldering-bench"
                   if approach == "soldering" else "bin/hashlock-bench")


def command_for(approach, args, case_dir):
    if approach == "soldering":
        command = [str(binary_path(approach)), "--mode",
                   "groth16" if args.mode == "prove" else "execute", "--wires", str(args.wires),
                   "--instances", str(args.instances), "--seed", str(args.seed), "--out", str(case_dir)]
        if args.mode == "prove":
            command += ["--artifacts", str(args.artifacts)]
        return command
    return [str(binary_path(approach)), "-wires", str(args.wires), "-mode", args.mode,
            "-seed", str(args.seed), "-out", str(case_dir)]


def preflight(args, env):
    if "soldering" not in approaches(args):
        return
    for key in ("SP1_DEV_MODE", "SP1_DISABLE_VK_VERIFICATION", "SP1_SKIP_PROGRAM_BUILD"):
        if key in env:
            raise ValueError(f"unset {key}; this runner requires a real, rebuilt SP1 guest")
    if env.get("SP1_PROVER", "cpu") != "cpu":
        raise ValueError("SP1_PROVER must be unset or cpu")
    if env.get("CARGO_TARGET_DIR"):
        raise ValueError("unset CARGO_TARGET_DIR; binaries must be built inside this repo")
    provenance = json.loads((ROOT / "soldering/source.json").read_text())
    for name, expected in provenance["guest_sha256"].items():
        if sha(ROOT / "soldering/guest" / name) != expected:
            raise ValueError(f"soldering guest differs from the pinned upstream source: {name}")
    if args.mode == "prove" and not args.build_only:
        if args.artifacts.name != "v5.0.0":
            raise ValueError("SP1 5.2.2 requires Groth16 artifacts in a directory named v5.0.0")
        for name in ("groth16_pk.bin", "groth16_circuit.bin", "groth16_vk.bin"):
            path = args.artifacts / name
            if not path.is_file() or not path.stat().st_size:
                raise ValueError(f"missing SP1 artifact: {path}; see soldering/README.md")


def logged_process(command, env, stdout_path, stderr_path, cwd=ROOT):
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                start_new_session=True)
        try:
            return proc.wait()
        except KeyboardInterrupt:
            # Also stop children of /usr/bin/time and Cargo, leaving checkpoints intact.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            raise


def build(args, env, out):
    commands = []
    if "soldering" in approaches(args):
        commands.append(("soldering", ["cargo", "build", "--locked", "--release",
                                      "--manifest-path", "soldering/host/Cargo.toml"]))
    if "hashlock" in approaches(args):
        commands += [("hashlock", ["go", "build", "-mod=readonly", "-o", "bin/hashlock-bench", "./cmd/bench"]),
                     ("hashlock-verifier", ["go", "build", "-mod=readonly", "-o", "bin/hashlock-verify", "./cmd/verify"])]
    for name, command in commands:
        print(f"Building {name} (outside benchmark timings)...", flush=True)
        write_json(out / f"build-{name}.command.json", command)
        code = logged_process(command, env, out / f"build-{name}.stdout.log", out / f"build-{name}.stderr.log")
        if code:
            raise RuntimeError(f"{name} build failed ({code}); see {out / f'build-{name}.stderr.log'}")


def metadata(args, env):
    sources = list(ROOT.glob("circuit/*.go")) + list(ROOT.glob("cmd/*/*.go"))
    sources += list(ROOT.glob("soldering/*/src/*.rs"))
    sources += list(ROOT.glob("soldering/*/Cargo.*")) + list(ROOT.glob("soldering/*/build.rs"))
    sources += [ROOT / name for name in ("go.mod", "go.sum", "run.py", "source.json",
                                         "soldering/source.json", "rust-toolchain.toml")]
    commands = [["go", "version"], ["rustc", "-Vv"], ["rustc", "+succinct", "-Vv"],
                ["cargo", "--version"], ["git", "status", "--short"]]
    if "hashlock" in approaches(args):
        commands += [["go", "version", "-m", str(binary_path("hashlock"))]]
    if sys.platform == "darwin":
        commands += [["sysctl", "-n", "machdep.cpu.brand_string"], ["sysctl", "-n", "hw.memsize"],
                     ["sysctl", "-n", "hw.logicalcpu"], ["pmset", "-g", "batt"], ["pmset", "-g", "custom"]]
    result = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "argv": sys.argv, "platform": platform.platform(), "logical_cpus": os.cpu_count(),
        "config": config(args), "environment": {k: env.get(k) for k in ENV_KEYS},
        "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted(sources)},
        "binary_sha256": {a: sha(binary_path(a)) for a in approaches(args)},
        "tools": [capture(command) for command in commands],
        "fixture_note": "Same numeric seed; different fixture generators and relations. Proof randomness is fresh.",
    }
    if "soldering" in approaches(args) and args.mode == "prove" and not args.build_only:
        result["sp1_artifacts"] = {
            "path": str(args.artifacts), "circuit_version": "v5.0.0",
            "vk_sha256": sha(args.artifacts / "groth16_vk.bin"),
            "file_bytes": {name: (args.artifacts / name).stat().st_size for name in
                           ("groth16_pk.bin", "groth16_circuit.bin", "groth16_vk.bin")},
        }
    return result


def config(args):
    return {"approaches": approaches(args), "mode": args.mode, "wires": args.wires,
            "soldering_retained_instances": args.instances, "hashlock_rows": 2 * args.wires,
            "threads": args.threads, "trials": args.trials, "seed": args.seed,
            "order": "sequential; reverse approach order on even trials"}


def normalize(approach, result, args, exit_code):
    """Reject partial/mismatched runs before exposing comparable proving timings."""
    def require(ok, message):
        if not ok:
            raise ValueError(message)

    require(exit_code == 0, f"process exited with {exit_code}")
    require(result.get("status") == "complete", "benchmark did not finish")
    require(result.get("wires") == args.wires, "wire count mismatch")
    timings = result.get("timings_s", {})

    def seconds(name):
        value = timings.get(name)
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                f"missing or invalid timing: {name}")
        return value

    item = {"status": "complete", "wires": args.wires, "retained_instances": None,
            "rows": None, "setup_s": None, "proof_generation_s": None, "verification_s": None,
            "serialized_proof_file_bytes": None, "timings_s": timings, "proof_verified": False}
    if approach == "soldering":
        require(result.get("mode") == ("groth16" if args.mode == "prove" else "execute"), "SP1 mode mismatch")
        require(result.get("total_retained_instances") == args.instances, "retained instance count mismatch")
        require(result.get("seed") == args.seed, "SP1 seed mismatch")
        require(result.get("guest_output_matches_host") is True, "SP1 output was not checked against the host")
        for key in ("RAYON_NUM_THREADS", "GOMAXPROCS"):
            require(result.get("environment", {}).get(key) == str(args.threads), f"SP1 {key} mismatch")
        item.update(retained_instances=args.instances, preimage_bytes=16,
                    sha256_evaluations=2 * args.wires * (args.instances + 1),
                    xor_translations=2 * args.wires * (args.instances - 1),
                    fixed_base_scalar_multiplications=0, guest_instructions=result.get("guest_instructions"),
                    public_values_bytes=result.get("public_values_bytes"))
        if args.mode == "prove":
            require(result.get("schema_version", 0) >= 2, "SP1 verification timer includes the negative test; rebuild")
            require({"core", "compressed", "groth16"}.issubset(result.get("verified_stages", [])),
                    "final SP1 Groth16 proof has not been verified")
            require(result.get("groth16_tampered_public_output_rejected") is True,
                    "SP1 tampered public output was not rejected")
            item.update(setup_s=seconds("key_setup"),
                        proof_generation_s=sum(seconds(k) for k in SP1_PROVE_STAGES),
                        verification_s=seconds("groth16_verify"), proof_verified=True,
                        serialized_proof_file_bytes=result.get("proof_bytes", {}).get("groth16_serialized"))
    else:
        require(result.get("mode") == args.mode, "hashlock mode mismatch")
        require(result.get("seed") == str(args.seed), "hashlock seed mismatch")
        require(result.get("rows") == 2 * args.wires, "hashlock must cover both values of every wire")
        require(result.get("cpu_workers") == args.threads, "Go worker count mismatch")
        require(result.get("scalar_range_check") is False, "hashlock circuit includes an unwanted scalar range check")
        item.update(rows=2 * args.wires, preimage_bytes=32, sha256_evaluations=2 * args.wires,
                    xor_translations=0, fixed_base_scalar_multiplications=2 * args.wires,
                    constraints=result.get("constraints"))
        if args.mode == "prove":
            for key in ("proof_verified", "altered_hash_rejected", "altered_point_rejected"):
                require(result.get(key) is True, f"hashlock check failed: {key}")
            item.update(setup_s=seconds("setup"), proof_generation_s=seconds("prove"),
                        verification_s=seconds("verify"), proof_verified=True,
                        serialized_proof_file_bytes=result.get("artifact_bytes", {}).get("proof.bin"))
        elif args.mode == "check":
            require(result.get("constraints_satisfied") is True, "hashlock witness does not satisfy the circuit")
    return item


def save_report(out, args, rows):
    status = "incomplete"
    if any(row["status"] == "failed" for row in rows):
        status = "failed"
    elif len(rows) == len(approaches(args)) * args.trials:
        status = "complete"
    write_json(out / "comparison.json", {"schema_version": 1, "status": status, "config": config(args), "results": rows})
    with (out / "comparison.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TABLE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    def number(value):
        return "—" if value is None else f"{value:.6f}"

    lines = ["# Local benchmark comparison", "", f"Comparison status: **{status}**.", "",
             f"Mode: **{args.mode}**. Wires: **{args.wires}**. Worker setting: **{args.threads}** for both runtimes.", "",
             f"Soldering uses {args.instances} total retained instances (including the base); hashlock consistency uses {2 * args.wires} rows.", "",
             "| Trial | Approach | Status | Setup (s) | Proving (s) | Final verification (s) | Process wall (s) | Peak RSS (GiB) |",
             "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in rows:
        rss = row.get("peak_rss_bytes")
        lines.append(f"| {row['trial']} | {row['approach']} | {row['status']} | " +
                     " | ".join(number(row.get(k)) for k in ("setup_s", "proof_generation_s", "verification_s", "process_wall_s")) +
                     f" | {number(rss / 2**30 if rss is not None else None)} |")
    lines += ["", "Proving excludes setup and verification. SP1 includes core proving, compression, shrink, BN254 wrapping and the final Groth16 wrapper. Final verification times one successful check; negative tests are separate.", "",
              "Setup is not the same operation: SP1 initializes program keys using pre-existing shared Groth16 artifacts; hashlock generates a local circuit-specific Groth16 test CRS. Artifact generation/download and compilation are excluded from proving. Process wall time includes preparation, checks, setup and serialization.", "",
              "These are different relations and prover stacks, with 16-byte soldering labels and 32-byte hashlock preimages. This compares the isolated approaches on the same wire count, not identical cryptographic work or complete bridge protocols. Serialized proof file sizes in CSV/JSON use different encodings.", ""]
    if args.mode != "prove":
        lines += ["**No proofs are generated in this mode. These are validation results, not proof-generation measurements.**", ""]
    errors = [f"- Trial {r['trial']}, {r['approach']}: {r['error']}" for r in rows if r.get("error")]
    if errors:
        lines += errors + [""]
    (out / "comparison.md").write_text("\n".join(lines))


def run_case(approach, args, env, out, trial):
    trial_dir = out / f"trial-{trial:03d}"
    trial_dir.mkdir(exist_ok=True)
    case_dir = trial_dir / approach
    command = command_for(approach, args, case_dir)
    timed = command
    if Path("/usr/bin/time").is_file():
        if sys.platform == "darwin":
            timed = ["/usr/bin/time", "-l", *command]
        elif sys.platform.startswith("linux"):
            timed = ["/usr/bin/time", "-v", *command]
    write_json(trial_dir / f"{approach}.command.json", timed)
    print(f"Starting trial {trial}, {approach}: {args.wires} wires, mode={args.mode}", flush=True)
    stderr = trial_dir / f"{approach}.stderr.log"
    start = time.monotonic()
    code = logged_process(timed, env, trial_dir / f"{approach}.stdout.log", stderr)
    elapsed = time.monotonic() - start
    log = stderr.read_text(errors="replace")
    rss = re.search(r"^\s*(\d+)\s+maximum resident set size", log, re.M)
    rss_bytes = int(rss[1]) if rss else None
    if sys.platform.startswith("linux"):
        rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", log)
        rss_bytes = int(rss[1]) * 1024 if rss else None
    item = {"trial": trial, "approach": approach, "wires": args.wires, "exit_code": code,
            "process_wall_s": elapsed, "peak_rss_bytes": rss_bytes,
            "result_path": str((case_dir / "result.json").relative_to(out))}
    try:
        result = json.loads((case_dir / "result.json").read_text())
        item.update(normalize(approach, result, args, code))
    except (ValueError, OSError) as exc:
        item.update(status="failed", error=str(exc))
        print(f"{approach} failed: {exc}\nSee {stderr}", file=sys.stderr)
    print(f"Finished {approach}: {item['status']}, wall={elapsed:.2f}s, proving={item.get('proof_generation_s')}", flush=True)
    return item


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approach", choices=["both", "soldering", "hashlock"], default="both")
    parser.add_argument("--mode", choices=["prove", "check", "compile"], default="prove",
                        help="check runs the SP1 guest and solves the native circuit; compile is hashlock-only")
    parser.add_argument("--wires", type=int, default=1019)
    parser.add_argument("--instances", type=int, default=7, help="total retained soldering instances, including base")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20261001)
    parser.add_argument("--artifacts", type=Path, default=Path.home() / ".sp1/circuits/groth16/v5.0.0")
    parser.add_argument("--out", type=Path, help="new result directory; existing directories are never overwritten")
    parser.add_argument("--build-only", action="store_true", help="compile binaries without running either benchmark")
    parser.add_argument("--dry-run", action="store_true", help="print the plan; do not build, prove or write files")
    args = parser.parse_args()
    if min(args.wires, args.threads, args.trials) < 1 or args.instances < 2:
        parser.error("wires, threads and trials must be positive; instances must be at least two")
    if not 0 <= args.seed < 2**64:
        parser.error("seed must be an unsigned 64-bit integer")
    if args.mode == "compile" and args.approach != "hashlock":
        parser.error("--mode compile requires --approach hashlock")
    args.artifacts = args.artifacts.expanduser().resolve()
    return args


def main():
    args = parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = (args.out or ROOT / "results" / f"{stamp}-{args.mode}-w{args.wires}").expanduser().resolve()
    if args.dry_run:
        print(json.dumps(config(args), indent=2))
        print("Build both selected binaries; no benchmarks." if args.build_only else "Build, then run sequentially:")
        if not args.build_only:
            for trial in range(1, args.trials + 1):
                order = approaches(args)[::1 if trial % 2 else -1]
                for approach in order:
                    print(shlex.join(command_for(approach, args, out / f"trial-{trial:03d}" / approach)))
        return 0
    env = os.environ.copy()
    env["GOMAXPROCS"] = env["RAYON_NUM_THREADS"] = str(args.threads)
    try:
        preflight(args, env)
        out.mkdir(parents=True, exist_ok=False)
    except (ValueError, OSError) as exc:
        print(f"Cannot start: {exc}", file=sys.stderr)
        return 1
    print(f"Results: {out}", flush=True)
    write_json(out / "run.json", {"status": "building", "config": config(args)})
    rows = []
    try:
        build(args, env, out)
        write_json(out / "environment.json", metadata(args, env))
        if args.build_only:
            write_json(out / "run.json", {"status": "build_complete", "config": config(args)})
            print("Build complete; no benchmark started.", flush=True)
            return 0
        save_report(out, args, rows)
        for trial in range(1, args.trials + 1):
            for approach in approaches(args)[::1 if trial % 2 else -1]:
                write_json(out / "run.json", {"status": "running", "trial": trial, "approach": approach, "config": config(args)})
                item = run_case(approach, args, env, out, trial)
                rows.append(item)
                save_report(out, args, rows)
                if item["status"] != "complete":
                    raise RuntimeError(f"trial {trial}, {approach} failed; comparison is incomplete")
        write_json(out / "run.json", {"status": "complete", "config": config(args)})
        print(f"Comparison: {out / 'comparison.md'}", flush=True)
        return 0
    except KeyboardInterrupt:
        write_json(out / "run.json", {"status": "interrupted", "config": config(args)})
        print(f"Stopped; logs and stage checkpoints remain in {out}.", file=sys.stderr)
        return 130
    except (RuntimeError, OSError, ValueError) as exc:
        write_json(out / "run.json", {"status": "failed", "error": str(exc), "config": config(args)})
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if sys.platform == "darwin":
            write_json(out / "power-after.json", capture(["pmset", "-g", "batt"]))


if __name__ == "__main__":
    raise SystemExit(main())
