"""
Measure the numbers that answer "your system is slow compared with 20 ms":

   python measure_latency.py                      (uses data/traffic.pcapng, 5 runs)
   python measure_latency.py --runs 10 --pcap data/traffic.pcapng

It reports, WITHOUT the capture step (capture is test-network time, not system latency):
  1. throughput of each stage (packets per second)
  2. cost per PACKET:        scoring (rules + AI), encryption
  3. cost per CONVERSATION:  key exchange (classical vs quantum-safe hybrid), scoring of its first packets
  4. OLD vs NEW method:      calling the AI model one packet at a time (milestone 2) vs all at once (now)
Results are printed as a table and saved to data/latency_report.json (paste them into your slides).
"""
import argparse
import json
import os
import statistics as st
import time

import numpy as np
import pandas as pd

import service
from feature_extraction import FeatureExtractor
import sensitivity_engine as se
from policy_engine import PolicyEngine
from encryption_engine import EncryptionEngine

OUT = "data/latency"


def med(xs):
    return st.median(xs) if xs else float("nan")


def timeit(fn, runs):
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return med(times), times


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default="data/traffic.pcapng")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--old-rows", type=int, default=100, help="packets used for the one-at-a-time comparison")
    a = ap.parse_args()
    if not os.path.exists(a.pcap):
        raise SystemExit(f"{a.pcap} not found. Run the pipeline once, or python make_sample_pcap.py")
    os.makedirs(OUT, exist_ok=True)
    rep = {"pcap": a.pcap, "runs": a.runs}

    with service.muted():
        # ---------- 1. features ----------
        fe = FeatureExtractor(); fe.output_file = f"{OUT}/features.csv"
        t_feat, _ = timeit(lambda: fe.extract_features(a.pcap), a.runs)
        df = pd.read_csv(fe.output_file)
        n = len(df)
        flows = df["Flow_ID"].nunique()
        rep.update(packets=n, conversations=int(flows), packets_per_conversation=round(n / max(flows, 1), 2))
        rep["features_s"] = t_feat

        # ---------- 2. scoring: rules only, AI only, both ----------
        model = se.get_cached_model(se.MODEL_PATH)
        S = se.load_settings()
        t_rules, _ = timeit(lambda: se.score_dataframe(df, None, S), a.runs)
        feat_df, *_ = se._build_feature_matrix(df)
        t_ai, _ = timeit(lambda: model.predict_batch(feat_df), a.runs)
        t_both, _ = timeit(lambda: se.score_dataframe(df, model, S), a.runs)
        rep.update(score_rules_only_s=t_rules, score_ai_only_s=t_ai, score_total_s=t_both)

        # ---------- 4. OLD method (one packet at a time, two model calls per packet) vs batched ----------
        k = min(a.old_rows, n)
        X = feat_df.reindex(columns=model.features, fill_value=0.0).apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=float)[:k]
        t0 = time.perf_counter()
        for i in range(k):
            model.model.predict(X[i:i + 1])
            model.model.predict_proba(X[i:i + 1])
        old_per_packet = (time.perf_counter() - t0) / k
        t0 = time.perf_counter()
        model.model.predict(X); model.model.predict_proba(X)
        new_per_packet = (time.perf_counter() - t0) / k
        rep.update(ai_old_method_ms_per_packet=old_per_packet * 1000, ai_batched_ms_per_packet=new_per_packet * 1000,
                   ai_speedup_x=old_per_packet / new_per_packet if new_per_packet else None, old_method_rows_used=k)

        # ---------- policy ----------
        res_file = f"{OUT}/results.csv"
        se_eng = se.SensitivityEngine(); se_eng.output_file = res_file
        se_eng.classify_sensitivity(fe.output_file)
        pol = PolicyEngine(output_file=f"{OUT}/policy.csv")
        t_pol, _ = timeit(lambda: pol.select_policies(res_file, force_resource="AVAILABLE"), a.runs)
        t0 = time.perf_counter(); from policy_engine import get_resource_status; get_resource_status(); rep["resource_reading_s"] = time.perf_counter() - t0
        rep["policy_s"] = t_pol

        # ---------- encryption ----------
        enc = EncryptionEngine(output_file=f"{OUT}/encrypted.csv")
        ok = None
        t_enc_runs = []
        for _ in range(a.runs):
            ok = enc.encrypt_traffic(f"{OUT}/policy.csv", a.pcap)
            t_enc_runs.append(enc.last_stats.get("wall_s", float("nan")) if ok else float("nan"))
        rep["encryption_s"] = med(t_enc_runs)
        rep["encryption_ok"] = bool(ok)
        if ok:
            e = pd.read_csv(f"{OUT}/encrypted.csv")
            us = pd.to_numeric(e["Encrypt_Time_us"], errors="coerce")
            us = us[us > 0]
            rep.update(encrypt_us_per_packet_median=float(us.median()), encrypt_us_per_packet_p95=float(us.quantile(0.95)), packets_encrypted=int(len(us)))
            hs = e[e["New_Flow_Handshake"] == True].copy()
            hs["ms"] = pd.to_numeric(hs["Handshake_Time_ms"], errors="coerce")
            hs["hybrid"] = hs["Key_Exchange_Used"].astype(str).str.contains("ML-KEM|Kyber|DEV-SIM")
            rep["keyexchange_ms_classical"] = float(hs[~hs["hybrid"]]["ms"].mean()) if (~hs["hybrid"]).any() else None
            rep["keyexchange_ms_hybrid"] = float(hs[hs["hybrid"]]["ms"].mean()) if hs["hybrid"].any() else None

    # ---------- derived numbers ----------
    stage_total = rep["score_total_s"] + rep["policy_s"] + rep.get("encryption_s", 0)
    rep["analysis_packets_per_second"] = n / (rep["features_s"] + stage_total) if stage_total else None
    rep["scoring_ms_per_packet"] = rep["score_total_s"] / n * 1000
    first_n = se.load_settings()["first_n"]
    rep["decision_ms_per_new_conversation_estimate"] = rep["scoring_ms_per_packet"] * min(first_n, rep["packets_per_conversation"])
    json.dump(rep, open("data/latency_report.json", "w"), indent=2)

    f = lambda v, d=2: "n/a" if v is None or (isinstance(v, float) and v != v) else f"{v:.{d}f}"
    print("\n" + "=" * 72 + f"\nLATENCY REPORT  ({n} packets, {flows} conversations, median of {a.runs} runs, capture excluded)\n" + "=" * 72)
    print(f"Features        : {f(rep['features_s'], 3)} s   -> {f(n / rep['features_s'], 0)} packets/s")
    print(f"Scoring total   : {f(rep['score_total_s'], 3)} s   -> {f(rep['scoring_ms_per_packet'], 3)} ms per packet")
    print(f"   rules only   : {f(rep['score_rules_only_s'], 3)} s   |  AI model only: {f(rep['score_ai_only_s'], 3)} s")
    print(f"Policy          : {f(rep['policy_s'], 3)} s   (+ {f(rep['resource_reading_s'], 2)} s once per run to read CPU/memory)")
    print(f"Encryption      : {f(rep.get('encryption_s'), 3)} s   ({'ok' if rep['encryption_ok'] else 'FAILED: is ML-KEM installed?'})")
    if rep["encryption_ok"]:
        print(f"   per packet   : median {f(rep['encrypt_us_per_packet_median'], 1)} µs, 95% under {f(rep['encrypt_us_per_packet_p95'], 1)} µs")
        print(f"   key exchange : classical {f(rep['keyexchange_ms_classical'], 3)} ms | hybrid quantum-safe {f(rep['keyexchange_ms_hybrid'], 3)} ms (once per conversation)")
    print(f"\nAI model, OLD way (one packet at a time) : {f(rep['ai_old_method_ms_per_packet'], 3)} ms per packet")
    print(f"AI model, NEW way (all packets at once)   : {f(rep['ai_batched_ms_per_packet'], 4)} ms per packet   -> {f(rep['ai_speedup_x'], 0)}x faster  (on {rep['old_method_rows_used']} packets)")
    print(f"\nEstimated decision cost for a NEW conversation (first {first_n} packets): {f(rep['decision_ms_per_new_conversation_estimate'], 2)} ms")
    print(f"End-to-end analysis speed (features+scoring+policy+encryption): {f(rep['analysis_packets_per_second'], 0)} packets/s")
    print("\nCompare with: ~20 ms network delay per packet (the supervisor's figure). Saved to data/latency_report.json\n")


if __name__ == "__main__":
    main()
