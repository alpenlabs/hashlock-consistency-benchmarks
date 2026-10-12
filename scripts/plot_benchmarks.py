#!/usr/bin/env python3
"""Regenerate the retained-instance chart and its README section from raw results."""
import argparse
import json
import math
from pathlib import Path

from build_tables import STARK, WRAP

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- benchmark-chart:start -->"
END = "<!-- benchmark-chart:end -->"
STEM = "proving-time-vs-retained-instances"


def load_run(path):
    record = json.loads(path.read_text())
    if (record.get("status") != "complete" or record.get("mode") != "groth16"
            or "groth16" not in record.get("verified_stages", [])):
        raise ValueError(f"{path}: a completed, verified Groth16 run is required")
    stages = [record["timings_s"][name] for name in (*STARK, *WRAP)]
    if any(not math.isfinite(value) or value <= 0 for value in stages):
        raise ValueError(f"{path}: invalid proving-stage duration")
    seconds = sum(stages)
    reported = record["proof_generation_s_excluding_setup_and_verification"]
    if not math.isclose(seconds, reported, rel_tol=1e-9):
        raise ValueError(f"{path}: total proving time disagrees with stage timings")
    return dict(record, case=path.parent.name, minutes=seconds / 60)


def load_data(results):
    soldering = [load_run(path) for path in sorted(results.glob("soldering-m*/result.json"))]
    if len(soldering) < 2:
        raise ValueError("At least two soldering runs are needed to plot retained-instance scaling")
    soldering.sort(key=lambda record: record["total_retained_instances"])
    instances = [record["total_retained_instances"] for record in soldering]
    if len(set(instances)) != len(instances) or min(instances) < 2:
        raise ValueError("Soldering runs must have distinct retained-instance counts of at least two")
    reference = load_run(results / "hashlock-sp1-secp256k1/result.json")
    if reference.get("curve") != "secp256k1" or reference.get("rows") != 2 * reference["wires"]:
        raise ValueError("The reference must use secp256k1 and two rows per input wire")
    records = soldering + [reference]
    for field in ("wires", "sp1_crates_version", "sp1_circuit_version", "host_arch", "host_os"):
        if len({record[field] for record in records}) != 1:
            raise ValueError(f"Cannot compare runs with different {field}")
    workers = {record["environment"]["RAYON_NUM_THREADS"] for record in records}
    if len(workers) != 1:
        raise ValueError("Cannot compare runs with different worker counts")

    # The result JSON carries workload/timings; the driver snapshots carry hardware.
    machines = {}
    for path in sorted(results.glob("environment-*.json")):
        snapshot = json.loads(path.read_text())
        outputs = {tuple(tool["command"]): tool.get("stdout", "").strip()
                   for tool in snapshot.get("tools", []) if tool.get("exit_code") == 0}
        cpu = outputs.get(("sysctl", "-n", "machdep.cpu.brand_string"))
        memory = outputs.get(("sysctl", "-n", "hw.memsize"))
        if cpu and memory:
            for case in snapshot["cases"]:
                machines[case] = (cpu, int(memory), snapshot["threads"])
    if any(record["case"] not in machines for record in records):
        raise ValueError("Missing CPU/memory snapshot for one or more plotted runs")
    hardware = {machines[record["case"]] for record in records}
    if len(hardware) != 1:
        raise ValueError("Cannot compare runs from different machines or thread counts")
    cpu, memory, threads = hardware.pop()
    if str(threads) != next(iter(workers)):
        raise ValueError("Hardware snapshot and result worker counts disagree")
    return soldering, reference, f"{cpu} · {memory / 2**30:g} GiB RAM · {threads} threads"


def draw_chart(soldering, reference, hardware, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator

    ink, muted, blue, orange = "#15283b", "#526171", "#2463a8", "#b75819"
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "text.color": ink, "axes.labelcolor": ink,
                         "xtick.color": muted, "ytick.color": muted,
                         "svg.fonttype": "none", "svg.hashsalt": STEM})
    fig, ax = plt.subplots(figsize=(10.4, 6.5), facecolor="white")
    fig.subplots_adjust(left=0.10, right=0.97, bottom=0.22, top=0.76)
    fig.text(0.10, 0.94, "Proof-generation time vs retained instances", fontsize=19, weight="bold")
    fig.text(0.10, 0.885,
             f"{reference['wires']:,} input positions · SP1 {reference['sp1_crates_version']} · CPU proving",
             fontsize=12, color=muted)

    x = [record["total_retained_instances"] for record in soldering]
    y = [record["minutes"] for record in soldering]
    ax.plot(x, y, color=blue, linewidth=2.4, marker="o", markersize=7,
            label="Soldering · measured runs", zorder=3)
    ax.axhline(reference["minutes"], color=orange, linewidth=2.1, linestyle=(0, (5, 3)),
               label="Hash consistency (secp256k1) · reference", zorder=2)
    for count, minutes in zip(x, y):
        ax.annotate(f"{minutes:.1f}", (count, minutes), xytext=(0, 11),
                    textcoords="offset points", ha="center", color=blue, weight="bold")
    ax.annotate(f"{reference['minutes']:.1f} min", (x[-1], reference["minutes"]),
                xytext=(0, -20), textcoords="offset points", ha="center",
                color=orange, weight="bold")
    ax.legend(loc="lower left", bbox_to_anchor=(-0.012, 1.025), frameon=False,
              ncol=1, fontsize=10, handlelength=2.6)
    ax.set_xticks(x)
    padding = max(0.18, (x[-1] - x[0]) * 0.08)
    ax.set_xlim(x[0] - padding, x[-1] + padding)
    ax.set_ylim(0, math.ceil((max(y + [reference["minutes"]]) + 3) / 5) * 5)
    ax.yaxis.set_major_locator(MultipleLocator(5))
    ax.set_xlabel("Retained instances (M)", labelpad=10)
    ax.set_ylabel("Proof-generation time (minutes)", labelpad=12)
    ax.grid(axis="y", color="#e5e9ee", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("bottom", "left"):
        ax.spines[side].set_color("#c5ccd4")
    ax.tick_params(length=0, pad=8)
    fig.text(0.10, 0.10, hardware + " · Groth16 wrapping included", fontsize=10, color=muted)
    fig.text(0.10, 0.06, "Hash-consistency proving work is independent of M at this fixed input size.",
             fontsize=9.5, color=muted)
    output.mkdir(parents=True, exist_ok=True)
    fig.savefig(output / f"{STEM}.png", dpi=220, facecolor="white")
    fig.savefig(output / f"{STEM}.svg", facecolor="white",
                metadata={"Date": None, "Creator": "scripts/plot_benchmarks.py"})
    plt.close(fig)


def readme_section(results, soldering, reference, hardware):
    result_link = results.relative_to(ROOT).as_posix()
    values = ", ".join(f"M={r['total_retained_instances']}: {r['minutes']:.1f} min" for r in soldering)
    return "\n".join([
        START, "## Proving time versus retained instances", "",
        f"![Soldering ({values}); hash consistency with secp256k1: {reference['minutes']:.1f} min, "
        f"a constant reference.](docs/figures/{STEM}.png)", "",
        f"{reference['wires']:,} input positions ({reference['rows']:,} position/value pairs), "
        f"SP1 {reference['sp1_crates_version']}, CPU proving. {hardware}. "
        "Proof-generation time includes STARK proving and both Groth16 wrapping stages; "
        "it excludes setup and verification. All plotted runs completed and their Groth16 proofs verified.", "",
        "The soldering markers show the measured proving times. The dashed hash-consistency line uses "
        "the measured runtime as a constant reference because that proof's workload is independent "
        "of the number of retained instances at a fixed input size. "
        "Garbling, polynomial commitments, and label reconstruction are outside these timings.", "",
        f"[Raw results]({result_link}/) · [PNG](docs/figures/{STEM}.png) · [SVG](docs/figures/{STEM}.svg)", "",
        "Regenerate the images and this README section together from the stored results (no proving runs):", "",
        "```sh", "python3 -m pip install -r scripts/requirements-plot.txt",
        f"python3 scripts/plot_benchmarks.py {result_link}", "```", END,
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="?", default=ROOT / "results/full-20261002")
    args = parser.parse_args()
    try:
        results = args.results.resolve()
        soldering, reference, hardware = load_data(results)
        section = readme_section(results, soldering, reference, hardware)
        readme = ROOT / "README.md"
        original = readme.read_text()
        if START in original or END in original:
            if original.count(START) != 1 or original.count(END) != 1 or original.index(START) >= original.index(END):
                raise ValueError("README chart markers must appear exactly once and in order")
            before, rest = original.split(START, 1)
            _, after = rest.split(END, 1)
            updated = before + section + after
        else:
            anchor = "## Soldering against BABE"
            if anchor not in original:
                raise ValueError("Cannot find the README insertion point for the chart")
            updated = original.replace(anchor, section + "\n\n" + anchor, 1)
        output = ROOT / "docs/figures"
        draw_chart(soldering, reference, hardware, output)
        readme.write_text(updated)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"error: {error}\n")
    print(f"Updated {readme.relative_to(ROOT)} and docs/figures/{STEM}.{{png,svg}}")
    for record in soldering:
        print(f"  Soldering M={record['total_retained_instances']}: {record['minutes']:.3f} min")
    print(f"  Hash consistency (secp256k1): {reference['minutes']:.3f} min (constant reference)")


if __name__ == "__main__":
    main()
