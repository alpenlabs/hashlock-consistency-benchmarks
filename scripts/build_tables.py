#!/usr/bin/env python3
"""Build comparison tables (markdown, CSV, JSON) from a full_runs.py results directory."""
import argparse
import csv
import json
from pathlib import Path

STARK = ("core_prove", "compress", "shrink")
WRAP = ("wrap_bn254", "groth16_wrap")
SP1_CASES = [("1", "Soldering (BitVM PR #75), M = 7", "soldering-m7"),
             ("3", "Hashlock, SP1, Baby Jubjub", "hashlock-sp1-babyjubjub"),
             ("4", "Hashlock, SP1, secp256k1", "hashlock-sp1-secp256k1")]
GIB = 2**30


def load(out, name):
    p = out / name / "result.json"
    return json.loads(p.read_text()) if p.is_file() else None


def summary_rows(out):
    p = out / "summary.json"
    return {r["case"]: r for r in json.loads(p.read_text())} if p.is_file() else {}


def fmt(v, digits=1):
    return "—" if v is None else f"{v:,.{digits}f}"


def minutes(s):
    return "—" if s is None else f"{s:,.0f} s ({s / 60:.1f} min)"


def sp1_row(num, label, case, out, summ):
    r, s = load(out, case), summ.get(case, {})
    if not r or r.get("status") != "complete":
        return {"#": num, "version": label, "status": (r or {}).get("status", "not run"),
                "stage": (r or {}).get("active_stage")}
    t = r["timings_s"]
    stark, wrap = sum(t[k] for k in STARK), sum(t[k] for k in WRAP)
    return {"#": num, "version": label, "status": "complete", "measured": True,
            "work": (f"{r['wires']} wires × {r['total_retained_instances']} instances"
                     if "total_retained_instances" in r else f"{r['rows']} rows"),
            "guest_instructions": r.get("guest_instructions"), "core_cycles": r.get("core_cycles"),
            "core_shards": r.get("core_shards"), "public_values_bytes": r.get("public_values_bytes"),
            "one_time_setup_s": t.get("key_setup"), "one_time_setup_kind": "SP1 program keys (Groth16 artifacts pre-made)",
            "stark_proving_s": stark, "groth16_wrapping_s": wrap, "proof_generation_s": stark + wrap,
            "verification_s": t.get("groth16_verify"), "peak_rss_bytes": s.get("peak_rss_bytes"),
            "proof_bytes": r.get("proof_bytes", {}).get("groth16_serialized"),
            "stage_timings_s": {k: t[k] for k in (*STARK, *WRAP) if k in t},
            "cycle_tracker": r.get("cycle_tracker")}


def gnark_points(out, summ):
    points = []
    for wires in (1, 256, 512):
        kg, pr = load(out, f"hashlock-gnark-w{wires}-keygen"), load(out, f"hashlock-gnark-w{wires}-prove")
        skg, spr = summ.get(f"hashlock-gnark-w{wires}-keygen", {}), summ.get(f"hashlock-gnark-w{wires}-prove", {})
        if not kg:
            continue
        points.append({
            "wires": wires, "rows": 2 * wires, "constraints": kg.get("constraints"),
            "keygen_status": kg.get("status"), "keygen_killed": skg.get("killed_by_memory_watchdog"),
            "compile_s": kg["timings_s"].get("compile"), "keygen_s": kg["timings_s"].get("setup"),
            "keygen_peak_rss_bytes": skg.get("peak_rss_bytes") or skg.get("watchdog_peak_group_rss_bytes"),
            "proving_key_bytes": kg.get("artifact_bytes", {}).get("proving-key-serialized-not-saved"),
            "prove_status": (pr or {}).get("status"), "prove_killed": spr.get("killed_by_memory_watchdog"),
            "prove_s": (pr or {}).get("timings_s", {}).get("prove"),
            "verify_s": (pr or {}).get("timings_s", {}).get("verify"),
            "prove_peak_rss_bytes": spr.get("peak_rss_bytes") or spr.get("watchdog_peak_group_rss_bytes"),
            "proof_verified": (pr or {}).get("proof_verified"),
            "proof_bytes": (pr or {}).get("artifact_bytes", {}).get("proof.bin")})
    return points


def extrapolate(points, full_constraints):
    """Linear in constraints through the two largest complete points (marginal rate)."""
    done = [p for p in points if p["keygen_status"] == "complete" and p["prove_status"] == "complete"]
    if len(done) < 2 or not full_constraints:
        return None
    a, b = sorted(done, key=lambda p: p["constraints"])[-2:]

    def line(key):
        if a[key] is None or b[key] is None:
            return None
        slope = (b[key] - a[key]) / (b["constraints"] - a["constraints"])
        return b[key] + slope * (full_constraints - b["constraints"])
    return {"basis_wires": [a["wires"], b["wires"]], "constraints": full_constraints,
            **{k: line(k) for k in ("keygen_s", "prove_s", "keygen_peak_rss_bytes", "prove_peak_rss_bytes",
                                    "proving_key_bytes")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    out = parser.parse_args().out.resolve()
    summ = summary_rows(out)
    sp1 = [sp1_row(*c, out, summ) for c in SP1_CASES]
    gnark = gnark_points(out, summ)
    compile_full = load(out, "hashlock-gnark-w1019-compile")
    full_constraints = (compile_full or {}).get("constraints")
    ext = extrapolate(gnark, full_constraints)
    # A Go heap limit makes key-generation memory sub-linear, so its extrapolation would understate it.
    limits = {}
    for p in gnark:
        cmd = out / f"hashlock-gnark-w{p['wires']}-keygen.command.json"
        if cmd.is_file():
            limits[p["wires"]] = json.loads(cmd.read_text()).get("env", {}).get("GOMEMLIMIT")
    capped = any(limits.values())
    report = {"sp1": sp1, "gnark_points": gnark, "gnark_full_compile": compile_full and {
        "constraints": full_constraints, "compile_s": compile_full["timings_s"].get("compile"),
        "peak_rss_bytes": summ.get("hashlock-gnark-w1019-compile", {}).get("peak_rss_bytes")},
        "gnark_full_extrapolated": ext}
    (out / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")

    with (out / "comparison.csv").open("w", newline="") as f:
        fields = ["#", "version", "status", "measured", "work", "guest_instructions", "constraints",
                  "one_time_setup_s", "stark_proving_s", "groth16_wrapping_s", "proof_generation_s",
                  "verification_s", "peak_rss_bytes", "proof_bytes"]
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in sp1:
            w.writerow(row)
        if ext:
            w.writerow({"#": "2", "version": "Hashlock, gnark (extrapolated)", "status": "extrapolated",
                        "measured": False, "work": "2038 rows", "constraints": ext["constraints"],
                        "one_time_setup_s": ext["keygen_s"], "proof_generation_s": ext["prove_s"],
                        "peak_rss_bytes": ext["prove_peak_rss_bytes"]})

    L = ["# Full-size comparison at 1,019 wires", "",
         "All runs: Apple M2 Max (12 cores, 64 GB), 12 threads, one trial each. SP1 5.2.2 with v5.0.0 Groth16 artifacts; gnark v0.14.0.", "",
         "| # | Version | Work | Guest cycles / constraints | One-time setup | Proof generation | Verification | Peak RSS | Proof |",
         "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    by_num = {r["#"]: r for r in sp1}
    for num in ("1", "2", "3", "4"):
        if num == "2":
            if ext:
                proof = next((p["proof_bytes"] for p in reversed(gnark) if p["proof_bytes"]), None)
                keygen_mem = ("> 64 GB (keys)" if capped else f"~{fmt(ext['keygen_peak_rss_bytes'] / GIB)} GiB (keys)")
                L.append(f"| 2 | Hashlock, gnark (**extrapolated**) | 2038 rows | {ext['constraints']:,} constraints | "
                         f"~{minutes(ext['keygen_s'])} key generation | ~{minutes(ext['prove_s'])} | — | "
                         f"~{fmt(ext['prove_peak_rss_bytes'] / GIB)} GiB (proof), {keygen_mem} | "
                         f"{proof:,} B (constant) |")
            else:
                L.append("| 2 | Hashlock, gnark | 2038 rows | — | — | — | — | — | not yet available |")
            continue
        r = by_num[num]
        if r.get("status") != "complete":
            L.append(f"| {num} | {r['version']} | — | — | — | — | — | — | {r['status']} ({r.get('stage')}) |")
            continue
        L.append(f"| {num} | {r['version']} | {r['work']} | {r['guest_instructions']:,} cycles | "
                 f"{fmt(r['one_time_setup_s'], 2)} s program keys | {minutes(r['proof_generation_s'])} | "
                 f"{fmt(r['verification_s'], 3)} s | {fmt(r['peak_rss_bytes'] / GIB if r['peak_rss_bytes'] else None)} GiB | "
                 f"{r['proof_bytes']:,} B |")
    L += ["", "SP1 proof generation is STARK proving (core, compress, shrink) plus Groth16 wrapping (BN254 wrap, Groth16 wrap). "
          "SP1's Groth16 keys are the pre-made v5.0.0 artifacts, so its one-time cost here is only program-key setup. "
          "gnark's one-time cost is circuit-specific Groth16 key generation, which a deployment would run once as a trusted setup. "
          "Proof sizes use different serializations (SP1 bincode of its Groth16 proof object; gnark's compressed proof with a BSB22 commitment).", "",
          "## SP1 stage breakdown", "",
          "| # | Version | Core | Compress | Shrink | BN254 wrap | Groth16 wrap | STARK proving | Groth16 wrapping | Core shards |",
          "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for r in sp1:
        if r.get("status") == "complete":
            t = r["stage_timings_s"]
            L.append(f"| {r['#']} | {r['version']} | " + " | ".join(fmt(t.get(k)) for k in (*STARK, *WRAP)) +
                     f" | {fmt(r['stark_proving_s'])} | {fmt(r['groth16_wrapping_s'])} | {r['core_shards']} |")
    trackers = [r for r in sp1 if r.get("cycle_tracker")]
    if trackers:
        L += ["", "## Hashlock guest cycle breakdown (millions of instructions)", "",
              "| # | Version | Table | Scalar mults | SHA-256 | Commit public output | Total guest |",
              "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
        for r in trackers:
            c = r["cycle_tracker"]
            L.append(f"| {r['#']} | {r['version']} | " + " | ".join(fmt(c.get(k, 0) / 1e6, 2) for k in
                     ("table", "scalar_mul", "sha256", "commit")) + f" | {r['guest_instructions'] / 1e6:.2f} |")
    L += ["", "## gnark bounded runs (key generation and proof generation in separate processes)", "",
          "| Wires | Rows | Constraints | Key generation | Key-gen peak RSS | Proving key | Proof generation | Proof peak RSS | Verified |",
          "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    for p in gnark:
        kill = " (killed by watchdog)" if p["keygen_killed"] or p["prove_killed"] else ""
        L.append(f"| {p['wires']} | {p['rows']} | {p['constraints']:,} | {fmt(p['keygen_s'])} s | "
                 f"{fmt((p['keygen_peak_rss_bytes'] or 0) / GIB)} GiB | {fmt((p['proving_key_bytes'] or 0) / 1e9, 2)} GB | "
                 f"{fmt(p['prove_s'], 2)} s | {fmt((p['prove_peak_rss_bytes'] or 0) / GIB)} GiB | {p['proof_verified']}{kill} |")
    if compile_full:
        L += ["", f"The full 1,019-wire circuit compiles to {full_constraints:,} constraints "
              f"({fmt(compile_full['timings_s'].get('compile'))} s, peak RSS "
              f"{fmt((summ.get('hashlock-gnark-w1019-compile', {}).get('peak_rss_bytes') or 0) / GIB)} GiB)."]
    if ext:
        L += ["", f"Row 2 extrapolates key-generation time, proof-generation time and proof-generation memory linearly in "
              f"constraints through the {ext['basis_wires'][0]}- and {ext['basis_wires'][1]}-wire runs. It is an estimate, "
              "not a measurement: the FFT domain grows to 2^26 at full size, and a 64 GB machine cannot hold the working set."]
        if capped:
            L += ["", f"The gnark runs used GOMEMLIMIT={next(v for v in limits.values() if v)}. The 512-wire key generation "
                  "peaked at the limit, so its memory is not extrapolated; it exceeds 64 GB because compiling the full circuit "
                  f"alone peaked at {fmt((summ.get('hashlock-gnark-w1019-compile', {}).get('peak_rss_bytes') or 0) / GIB)} GiB and the 128-wire GC trace puts the live heap at about 1.1 KiB per constraint "
                  "(about 61 GiB at full size) before the proving key is written out."]
    (out / "comparison.md").write_text("\n".join(L) + "\n")
    print((out / "comparison.md").read_text())


if __name__ == "__main__":
    main()
