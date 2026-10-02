#!/usr/bin/env python3
"""Run the full-size comparison cases one at a time, with a memory watchdog.

Each case gets its own benchmark output directory, logs, command and peak-memory
record. A case that exceeds the memory limit is killed and recorded, and the
driver moves on to the next case.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = Path.home() / ".sp1/circuits/groth16/v5.0.0"
SOLDERING = ROOT / "soldering/host/target/release/soldering-bench"
HASHLOCK_SP1 = ROOT / "hashlock-sp1/host/target/release/hashlock-sp1-bench"
HASHLOCK_GNARK = ROOT / "bin/hashlock-bench"


def cases(args, out):
    sp1 = ["--mode", "groth16", "--wires", "1019", "--artifacts", str(ARTIFACTS)]
    table = {
        **{f"soldering-m{m}": [str(SOLDERING), *sp1, "--instances", str(m), "--seed", "20261001",
                               "--out", str(out / f"soldering-m{m}")] for m in (5, 6, 7)},
        "hashlock-sp1-secp256k1": [str(HASHLOCK_SP1), *sp1, "--curve", "secp256k1",
                                   "--out", str(out / "hashlock-sp1-secp256k1")],
        "hashlock-sp1-babyjubjub": [str(HASHLOCK_SP1), *sp1, "--curve", "babyjubjub",
                                    "--statement", str(ROOT / "results/hashlock-sp1-statements/w1019.json"),
                                    "--out", str(out / "hashlock-sp1-babyjubjub")],
    }
    # Compile-only at full size gives the exact constraint count used for extrapolation.
    table["hashlock-gnark-w1019-compile"] = [str(HASHLOCK_GNARK), "-wires", "1019", "-mode", "compile",
                                             "-out", str(out / "hashlock-gnark-w1019-compile")]
    # Key generation and proof generation run as separate processes so each peak is measured alone.
    for wires in (1, 256, 512):
        keys = str(out / f"hashlock-gnark-w{wires}-keys")
        for step, mode in (("keygen", "setup"), ("prove", "prove")):
            name = f"hashlock-gnark-w{wires}-{step}"
            table[name] = [str(HASHLOCK_GNARK), "-wires", str(wires), "-mode", mode, "-keys", keys,
                           "-out", str(out / name)]
    return [(name, table[name]) for name in args.cases]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def capture(command):
    try:
        p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        return {"command": command, "exit_code": p.returncode, "stdout": p.stdout.strip()}
    except OSError as exc:
        return {"command": command, "error": str(exc)}


def group_rss_bytes(pgid):
    p = subprocess.run(["ps", "-A", "-o", "pgid=,rss="], capture_output=True, text=True)
    total = 0
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == str(pgid):
            total += int(parts[1]) * 1024
    return total


def run_case(name, command, out, env, limit_bytes):
    timed = ["/usr/bin/time", "-l", *command]
    (out / f"{name}.command.json").write_text(json.dumps({"command": timed, "env": {
        k: env.get(k) for k in ("RAYON_NUM_THREADS", "GOMAXPROCS", "GOMEMLIMIT", "RUST_LOG")}}, indent=2) + "\n")
    print(f"{datetime.datetime.now(datetime.timezone.utc):%H:%M:%SZ} start {name}", flush=True)
    start = time.monotonic()
    watchdog_peak, killed = 0, False
    with (out / f"{name}.stdout.log").open("w") as so, (out / f"{name}.stderr.log").open("w") as se:
        proc = subprocess.Popen(timed, cwd=ROOT, env=env, stdout=so, stderr=se, start_new_session=True)
        while proc.poll() is None:
            rss = group_rss_bytes(proc.pid)
            watchdog_peak = max(watchdog_peak, rss)
            if rss > limit_bytes:
                killed = True
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                break
            time.sleep(5)
    wall = time.monotonic() - start
    log = (out / f"{name}.stderr.log").read_text(errors="replace")
    rss = re.search(r"^\s*(\d+)\s+maximum resident set size", log, re.M)
    result_path = out / name / "result.json"
    result = json.loads(result_path.read_text()) if result_path.is_file() else {}
    row = {"case": name, "exit_code": proc.returncode, "killed_by_memory_watchdog": killed,
           "memory_limit_bytes": limit_bytes, "process_wall_s": wall,
           "peak_rss_bytes": int(rss[1]) if rss else None, "watchdog_peak_group_rss_bytes": watchdog_peak,
           "status": result.get("status", "failed"), "active_stage": result.get("active_stage"),
           "timings_s": result.get("timings_s", {})}
    print(f"{datetime.datetime.now(datetime.timezone.utc):%H:%M:%SZ} end {name}: status={row['status']} exit={proc.returncode} "
          f"killed={killed} wall={wall:.0f}s", flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", required=True)
    parser.add_argument("--threads", type=int, default=12)
    parser.add_argument("--memory-limit-gib", type=float, default=52)
    parser.add_argument("--gomemlimit")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(RAYON_NUM_THREADS=str(args.threads), GOMAXPROCS=str(args.threads), RUST_LOG="warn")
    if args.gomemlimit:
        env["GOMEMLIMIT"] = args.gomemlimit
    for key in ("SP1_DEV_MODE", "SP1_PROVER", "SP1_DISABLE_VK_VERIFICATION"):
        if key in env:
            sys.exit(f"unset {key}")
    selected = cases(args, out)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    binaries = {str(Path(c[0]).relative_to(ROOT)): sha(c[0]) for _, c in selected}
    (out / f"environment-{stamp}.json").write_text(json.dumps({
        "started_utc": stamp, "argv": sys.argv, "cases": [n for n, _ in selected],
        "threads": args.threads, "memory_limit_gib": args.memory_limit_gib, "gomemlimit": args.gomemlimit,
        "binary_sha256": binaries, "sp1_groth16_vk_sha256": sha(ARTIFACTS / "groth16_vk.bin"),
        "tools": [capture(c) for c in (["go", "version"], ["rustc", "-V"], ["rustc", "+succinct", "-V"],
                                       ["sysctl", "-n", "machdep.cpu.brand_string"], ["sysctl", "-n", "hw.memsize"],
                                       ["pmset", "-g", "batt"])],
    }, indent=2) + "\n")
    summary_path = out / "summary.json"
    rows = json.loads(summary_path.read_text()) if summary_path.is_file() else []
    for name, command in selected:
        if (out / name).exists():
            print(f"skip {name}: output exists", flush=True)
            continue
        rows.append(run_case(name, command, out, env, int(args.memory_limit_gib * 2**30)))
        summary_path.write_text(json.dumps(rows, indent=2) + "\n")
    print("all cases finished", flush=True)


if __name__ == "__main__":
    main()
