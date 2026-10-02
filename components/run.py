#!/usr/bin/env python3
"""Run the component micro-benchmarks (SP1 core+compressed proofs, gnark Groth16) sequentially."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SP1 = ROOT / "components/sp1/host/target/release/components-sp1-bench"
GNARK = ROOT / "bin/components-gnark"
SP1_OPS = ["noop", "sha256-precompile", "sha256-software", "xor128", "fr-mul-precompile",
           "secp256k1-fixed-base-mul", "commit-32b", "bjj-fixed-base-mul"]
# Larger N where the circuit stays small; SHA-256 and emulated secp256k1 would exceed memory at 1000.
GNARK_OPS = {"fr-mul": 1000, "xor128": 1000, "bjj-fixed-base-mul": 1000, "sha256": 200,
             "secp256k1-fixed-base-mul": 100}


def run(name, command, out, env):
    case = out / name
    if case.exists():
        print(f"skip {name}", flush=True)
        return
    timed = ["/usr/bin/time", "-l", *command]
    (out / f"{name}.command.json").write_text(json.dumps(timed, indent=2) + "\n")
    print(f"{datetime.datetime.now(datetime.timezone.utc):%H:%M:%SZ} start {name}", flush=True)
    with (out / f"{name}.stdout.log").open("w") as so, (out / f"{name}.stderr.log").open("w") as se:
        code = subprocess.run(timed, cwd=ROOT, env=env, stdout=so, stderr=se).returncode
    log = (out / f"{name}.stderr.log").read_text(errors="replace")
    rss = re.search(r"^\s*(\d+)\s+maximum resident set size", log, re.M)
    (out / f"{name}.rss").write_text(f"{rss[1] if rss else ''}\n")
    print(f"{datetime.datetime.now(datetime.timezone.utc):%H:%M:%SZ} end {name} exit={code}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=12)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(RAYON_NUM_THREADS=str(args.threads), GOMAXPROCS=str(args.threads), RUST_LOG="warn")
    for op, n in GNARK_OPS.items():
        for size in (1, n):
            run(f"gnark-{op}-n{size}", [str(GNARK), "bench", "-op", op, "-n", str(size), "-mode", "prove",
                                        "-out", str(out / f"gnark-{op}-n{size}")], out, env)
    for op in SP1_OPS:
        for size in (0, 1000):
            command = [str(SP1), "--op", op, "--n", str(size), "--mode", "compressed",
                       "--out", str(out / f"sp1-{op}-n{size}")]
            if op == "bjj-fixed-base-mul":
                oracle = subprocess.run([str(GNARK), "oracle", "-op", op, "-n", str(size)], cwd=ROOT,
                                        capture_output=True, text=True, check=True).stdout.strip()
                command += ["--bjj-oracle", oracle]
            run(f"sp1-{op}-n{size}", command, out, env)
    print("components finished", flush=True)


if __name__ == "__main__":
    main()
