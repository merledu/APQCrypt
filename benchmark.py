"""
Fair 3-way comparison on the SAME recorded traffic:
  static_aes : X25519 + AES-256-GCM for everything          (normal / today)
  static_pqc : X25519 + ML-KEM-1024 + AES-256-GCM for all   (everything quantum-safe)
  adaptive   : APQCrypt decision matrix

Run:  python3 benchmark.py --runs 5
Needs data/results.csv and data/traffic.pcapng from one normal pipeline run first.
"""
import os
import sys
import gc
import json
import argparse
import pandas as pd

from policy_engine import PolicyEngine
from encryption_engine import EncryptionEngine
from status_manager import StatusManager

MODES = ["static_aes", "static_pqc", "adaptive"]
LABELS = {"static_aes": "A. Normal (static AES-256-GCM)",
          "static_pqc": "B. Everything quantum-safe",
          "adaptive": "C. APQCrypt (adaptive)"}


def run_benchmark(runs=5, results_file="data/results.csv", pcap_file="data/traffic.pcapng", force_resource=None):
    # The engines report progress through StatusManager. During the comparison we MUTE it,
    # so the dashboard's pipeline bar and timings.json are not disturbed.
    saved = (StatusManager.__dict__["update_status"], StatusManager.__dict__["record_module_timing"])
    StatusManager.update_status = staticmethod(lambda *a, **k: None)
    StatusManager.record_module_timing = staticmethod(lambda *a, **k: None)
    try:
        return _run_benchmark(runs, results_file, pcap_file, force_resource)
    finally:
        StatusManager.update_status = saved[0]
        StatusManager.record_module_timing = saved[1]


def _run_benchmark(runs, results_file, pcap_file, force_resource):
    for f in (results_file, pcap_file):
        if not os.path.exists(f):
            raise FileNotFoundError(f"{f} not found. Run the normal pipeline once first.")
    os.makedirs("data/bench", exist_ok=True)

    rows = []
    for r in range(-1, runs):                      # r = -1 is a warm-up run (thrown away)
        order = MODES if r < 0 else MODES[r % 3:] + MODES[:r % 3]   # rotate order to avoid bias
        for mode in order:
            gc.collect()
            pol = PolicyEngine(output_file=f"data/bench/{mode}_policy.csv")
            enc = EncryptionEngine(output_file=f"data/bench/{mode}_encrypted.csv")
            pf = pol.select_policies(results_file, mode=mode, force_resource=force_resource)
            if not pf:
                raise RuntimeError(f"policy failed for {mode}")
            ef = enc.encrypt_traffic(pf, pcap_file)
            if not ef:
                raise RuntimeError(f"encryption failed for {mode}")
            if r < 0:
                continue
            s = enc.last_stats
            res = pd.read_csv(pf, usecols=["Resource_Status"])["Resource_Status"].iloc[0]
            rows.append({"run": r + 1, "mode": mode, "label": LABELS[mode], "resource": res,
                         "wall_s": s["wall_s"], "cpu_s": s["cpu_s"], "mem_mb": s["mem_mb"],
                         "handshake_ms": s["handshake_ms_total"], "encrypt_ms": s["encrypt_ms_total"],
                         "overhead_bytes": s["overhead_bytes"], "pq_flow_share": s["pq_flow_share"],
                         "high_pq_coverage": s["high_pq_coverage"], "flows": s["flows"], "packets": s["packets"],
                         "tamper_caught": s["checks"]["tamper_detected"], "tamper_missed": s["checks"]["tamper_missed"]})
            print(f"run {r + 1}/{runs} {mode:10s} wall={s['wall_s']}s cpu={s['cpu_s']}s hs={s['handshake_ms_total']}ms")

    runs_df = pd.DataFrame(rows)
    runs_df.to_csv("data/benchmark_runs.csv", index=False)

    metrics = ["wall_s", "cpu_s", "mem_mb", "handshake_ms", "encrypt_ms", "overhead_bytes", "pq_flow_share", "high_pq_coverage"]
    g = runs_df.groupby("label")[metrics]
    summary = g.mean().round(4).add_suffix("_mean").join(g.std().round(4).add_suffix("_std"))
    summary["tamper_missed_total"] = runs_df.groupby("label")["tamper_missed"].sum()
    summary = summary.reset_index()
    summary.to_csv("data/benchmark_summary.csv", index=False)
    with open("data/benchmark_summary.json", "w") as f:
        json.dump({"runs": runs, "rows": summary.astype(object).where(summary.notna(), None).to_dict("records")}, f, indent=2)
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--force-resource", choices=["AVAILABLE", "CONSTRAINED"], default=None)
    a = ap.parse_args()
    out = run_benchmark(a.runs, force_resource=a.force_resource)
    pd.set_option("display.width", 200)
    print("\n=== SUMMARY (mean over runs) ===")
    print(out.to_string(index=False))
