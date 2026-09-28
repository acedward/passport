#!/usr/bin/env python3
"""bench-report.py — the P2.4 table from prove-bench.sh's output (AA project 00040).

    python3 contract/scripts/minocrab/bench-report.py <prove-bench out dir> <bench.json>

Per (circuit, arm): k, rows (from the port's gate reports / the compactc pins, passed in below),
prover-key size, the median of the N timed proofs, and the proof server's peak memory: the largest
`docker stats` sample (1 s cadence) inside each timed request, the median of those peaks, and the
maximum over the whole arm (warm-up included). The proof server is a fresh container per arm.
"""
import json
import os
import statistics
import sys

ROWS = {
    ("append_inbox_with_evm", "compactc"): (18, 160236),
    ("append_inbox_with_evm", "minocrab"): (17, 85637),
    ("withdraw_shielded_with_evm", "compactc"): (18, 182809),
    ("withdraw_shielded_with_evm", "minocrab"): (17, 94639),
}


def mem_samples(path):
    out = []
    with open(path) as f:
        next(f)
        for line in f:
            ms, b = line.strip().split(",")
            out.append((int(ms), int(b)))
    return out


def main():
    d, dest = sys.argv[1], sys.argv[2]
    rows = []
    for (circuit, arm), (k_expected, n_rows) in ROWS.items():
        runs_file = os.path.join(d, f"{circuit}.{arm}.runs.json")
        if not os.path.exists(runs_file):
            continue
        r = json.load(open(runs_file))
        mem = mem_samples(os.path.join(d, f"{circuit}.{arm}.mem.csv"))
        timed = [x for x in r["runs"] if not x["warmup"]]
        peaks = []
        for x in timed:
            inside = [b for ms, b in mem if x["startMs"] - 500 <= ms <= x["endMs"] + 500]
            peaks.append(max(inside) if inside else None)
        arm_peak = max((b for _, b in mem), default=None)
        secs = [x["ms"] / 1000 for x in timed]
        rows.append({
            "circuit": circuit,
            "arm": arm,
            "k": r["k"],
            "k_expected": k_expected,
            "rows": n_rows,
            "prover_key_bytes": r["proverKeyBytes"],
            "prover_key_sha256": r["proverKeySha256"],
            "verifier_key_sha256": r["verifierKeySha256"],
            "n": len(timed),
            "prove_seconds": [round(s, 2) for s in secs],
            "median_prove_seconds": round(statistics.median(secs), 2) if secs else None,
            "warmup_prove_seconds": round(r["runs"][0]["ms"] / 1000, 2),
            "peak_mem_bytes_per_run": peaks,
            "median_peak_mem_gib": round(statistics.median([p for p in peaks if p]) / 2**30, 2) if any(peaks) else None,
            "max_mem_gib_whole_arm": round(arm_peak / 2**30, 2) if arm_peak else None,
            "memory_samples": len(mem),
            "check_skips_sha256": r["checkSkipsSha256"],
            "preimage_sha256": r["preimageSha256"],
            "proof_bytes": r["runs"][0]["proofBytes"],
            "proof_server": r["proofServer"]["version"],
        })
    # Same statement shape on both arms: /check's skip vector per circuit.
    for c in {x["circuit"] for x in rows}:
        s = {x["check_skips_sha256"] for x in rows if x["circuit"] == c}
        for x in rows:
            if x["circuit"] == c:
                x["check_skips_equal_across_arms"] = len(s) == 1
    ratios = {}
    for c in {x["circuit"] for x in rows}:
        a = {x["arm"]: x for x in rows if x["circuit"] == c}
        if "compactc" in a and "minocrab" in a:
            ratios[c] = {
                "prove_time_minocrab_over_compactc": round(a["minocrab"]["median_prove_seconds"] / a["compactc"]["median_prove_seconds"], 3),
                "prover_key_minocrab_over_compactc": round(a["minocrab"]["prover_key_bytes"] / a["compactc"]["prover_key_bytes"], 3),
                "peak_mem_minocrab_over_compactc": round(a["minocrab"]["median_peak_mem_gib"] / a["compactc"]["median_peak_mem_gib"], 3)
                if a["minocrab"]["median_peak_mem_gib"] and a["compactc"]["median_peak_mem_gib"] else None,
            }
    out = {
        "what": "AA 00040 P2.4 paired benchmark: compactc 0.34.0 vs MinoCrab 9f4d6a6, same preimage, proof server 9.0.0-rc.6 (fresh container per arm, 14 GiB cap)",
        "rows": rows,
        "ratios": ratios,
    }
    with open(dest, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print("| circuit | arm | k | rows | prover key MB | median prove s (N) | median peak mem GiB | max mem GiB |")
    print("|---|---|---|---|---|---|---|---|")
    for x in rows:
        print(f"| {x['circuit']} | {x['arm']} | {x['k']} | {x['rows']:,} | {x['prover_key_bytes'] / 1e6:.1f} | "
              f"{x['median_prove_seconds']} ({x['n']}) | {x['median_peak_mem_gib']} | {x['max_mem_gib_whole_arm']} |")
    print(json.dumps(ratios, indent=2))


if __name__ == "__main__":
    main()
