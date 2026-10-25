#!/usr/bin/env python3
"""
One MEASURED run of one encryption mode, in its OWN fresh process (so memory is measured honestly).
Started by comparison.py; you normally do not run it by hand.

  python comparison_worker.py --mode static_aes|static_pqc|adaptive --pcap data/traffic.pcapng [--force AVAILABLE|CONSTRAINED|none]
  python comparison_worker.py --micro            (algorithm costs: X25519, ML-KEM, AES-GCM, ChaCha20-Poly1305, HKDF)

It prints one line:  RESULT_JSON:{...}
What is timed (after the imports): reading the capture into conversations (parse), then, only for adaptive, the
decision (AI model load, scoring, computer-condition reading, policy), then key exchange + encryption of every packet.
"""
import argparse
import json
import os
import platform
import shutil
import statistics as st
import sys
import tempfile
import time
import traceback


def _vm_kb(key):
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith(key + ":"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def peak_mb():
    v = _vm_kb("VmHWM")
    if v is None:
        try:
            import resource
            v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except Exception:
            return None
    return round(v / 1024, 1)


def rss_mb():
    v = _vm_kb("VmRSS")
    return round(v / 1024, 1) if v else None


def out(res):
    print("RESULT_JSON:" + json.dumps(res, default=str))


# --------------------------------------------------------------------------- micro benchmark
def micro():
    res = {"kind": "micro", "ok": True, "rows": [], "notes": []}

    def bench(fn, n):
        for _ in range(min(5, n)):
            fn()
        ts = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            fn()
            ts.append(time.perf_counter_ns() - t0)
        return st.median(ts) / 1000.0, sorted(ts)[int(0.95 * (len(ts) - 1))] / 1000.0          # median µs, p95 µs

    def add(group, op, med_us, p95_us, detail=""):
        res["rows"].append({"group": group, "operation": op, "median_us": round(med_us, 2), "p95_us": round(p95_us, 2), "detail": detail})

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        pb = b.public_key()
        m, p = bench(lambda: X25519PrivateKey.generate(), 400); add("Key exchange (normal)", "X25519 key generation", m, p)
        m, p = bench(lambda: a.exchange(pb), 400); add("Key exchange (normal)", "X25519 shared secret", m, p)
        ikm = os.urandom(64)
        m, p = bench(lambda: HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x").derive(ikm), 400)
        add("Key making", "HKDF-SHA256 (one key)", m, p)
        data = os.urandom(1400)
        nonce = os.urandom(12)
        for name, cls, klen in (("AES-256-GCM", AESGCM, 32), ("AES-128-GCM", AESGCM, 16), ("ChaCha20-Poly1305", ChaCha20Poly1305, 32)):
            aead = cls(os.urandom(klen))
            m, p = bench(lambda: aead.encrypt(nonce, data, b"aad"), 3000)
            add("Encrypt one 1400-byte packet", name, m, p, f"about {1400 / m:.1f} MB/s")
    except Exception as e:
        res.update(ok=False, error=f"classical crypto test failed: {e}")
        out(res)
        return
    try:
        import oqs
        for label, names in (("ML-KEM-768", ["ML-KEM-768", "Kyber768"]), ("ML-KEM-1024", ["ML-KEM-1024", "Kyber1024"])):
            done = False
            for nm in names:
                try:
                    kem_a, kem_b = oqs.KeyEncapsulation(nm), oqs.KeyEncapsulation(nm)
                    pk = kem_a.generate_keypair()
                    ct, _ = kem_a.encap_secret(pk)
                    m, p = bench(lambda: kem_b.generate_keypair(), 150); add("Quantum-safe key exchange", f"{label} key generation", m, p, nm)
                    m, p = bench(lambda: kem_a.encap_secret(pk), 150); add("Quantum-safe key exchange", f"{label} encapsulate", m, p, nm)
                    m, p = bench(lambda: kem_a.decap_secret(ct), 150); add("Quantum-safe key exchange", f"{label} decapsulate", m, p, nm)
                    done = True
                    break
                except Exception:
                    continue
            if not done:
                res["notes"].append(f"{label} is not available in this liboqs build")
    except Exception as e:
        res["notes"].append(f"ML-KEM not measured: liboqs is not installed ({str(e)[:80]})")
    out(res)


# --------------------------------------------------------------------------- one measured run
def hs_bytes(label):
    """Key-exchange data one conversation sends (public keys + ciphertext), from the published sizes (FIPS 203, X25519)."""
    if "ML-KEM-1024" in label or "Kyber1024" in label:
        return 64 + 1568 + 1568
    if "ML-KEM-768" in label or "Kyber768" in label:
        return 64 + 1184 + 1088
    return 64                                              # X25519: two 32-byte public keys


def run(mode, pcap, force):
    res = {"kind": "run", "mode": mode, "ok": False, "error": None, "valid": False, "invalid_reason": None}
    tmp = tempfile.mkdtemp(prefix="apq_cmp_")
    try:
        t_imp = time.perf_counter()
        import pandas as pd
        import service
        import interfaces
        from feature_extraction import FeatureExtractor
        from policy_engine import PolicyEngine, get_resource_status
        from encryption_engine import EncryptionEngine
        if mode == "adaptive":
            import sensitivity_engine as se
        res["import_s"] = round(time.perf_counter() - t_imp, 3)
        res["mem_after_imports_mb"] = rss_mb()
        res["provider"] = interfaces.active_name("crypto_provider")

        def one_pass(tag):
            """The measured work. It is run twice: the first pass is a cold start, the second a 'service already running' pass."""
            ph = {"parse_s": 0.0, "model_load_s": 0.0, "scoring_s": 0.0, "resource_read_s": 0.0, "policy_s": 0.0, "encryption_total_s": 0.0}
            info = {}
            with service.muted():
                cpu0, wall0 = time.process_time(), time.perf_counter()
                if mode == "adaptive" and force == "none":
                    from policy_engine import prefetch_resource_status
                    prefetch_resource_status()      # the CPU reading waits in the background, as in the live pipeline
                t = time.perf_counter()
                fe = FeatureExtractor()
                fe.output_file = os.path.join(tmp, f"features_{tag}.csv")
                feat = fe.extract_features(pcap)
                if not feat:
                    raise RuntimeError("could not read the capture file")
                df = pd.read_csv(feat)
                ph["parse_s"] = time.perf_counter() - t
                info["packets"], info["conversations"] = int(len(df)), int(df["Flow_ID"].nunique())
                results_file = os.path.join(tmp, f"results_{tag}.csv")
                if mode == "adaptive":
                    t = time.perf_counter()
                    model = se.get_cached_model(se.MODEL_PATH)
                    ph["model_load_s"] = time.perf_counter() - t
                    info["model_loader"] = getattr(model, "loader", "?")
                    t = time.perf_counter()
                    eng = se.SensitivityEngine()
                    eng.output_file = results_file
                    if not eng.classify_sensitivity(feat):
                        raise RuntimeError("sensitivity scoring failed")
                    ph["scoring_s"] = time.perf_counter() - t
                    t = time.perf_counter()
                    rs = get_resource_status(None if force == "none" else force)      # forced = no waiting
                    ph["resource_read_s"] = time.perf_counter() - t
                    info["rs"] = rs
                    t = time.perf_counter()
                    pol_file = PolicyEngine(output_file=os.path.join(tmp, f"policy_{tag}.csv")).select_policies(
                        results_file, mode="adaptive", force_resource=rs["status"])
                    ph["policy_s"] = time.perf_counter() - t
                else:
                    t = time.perf_counter()
                    mini = df[["Pkt_Index", "Flow_ID", "Protocol", "Dest_Port"]].copy()
                    mini["Sensitivity"] = "UNSCORED"                       # static modes do not score anything
                    mini.to_csv(results_file, index=False)
                    pol_file = PolicyEngine(output_file=os.path.join(tmp, f"policy_{tag}.csv")).select_policies(
                        results_file, mode=mode, force_resource="AVAILABLE")      # static: no CPU reading needed
                    ph["policy_s"] = time.perf_counter() - t
                if not pol_file:
                    raise RuntimeError("policy step failed")
                t = time.perf_counter()
                enc = EncryptionEngine(output_file=os.path.join(tmp, f"enc_{tag}.csv"))
                enc.checks_file = None
                ok = enc.encrypt_traffic(pol_file, pcap)
                ph["encryption_total_s"] = time.perf_counter() - t
                total, cpu = time.perf_counter() - wall0, time.process_time() - cpu0
                if not ok:
                    raise RuntimeError("encryption failed (is liboqs installed? quantum-safe modes need it)")
            ph["decision_s"] = (ph["model_load_s"] + ph["scoring_s"] + ph["policy_s"]) if mode == "adaptive" else 0.0     # only adaptive decides; without the CPU-sampling wait
            return ph, total, cpu, enc, info

        # ---------------- first pass: cold start, the numbers shown as "first start" ----------------
        ph, total, cpu, enc, info = one_pass("a")
        res.update(packets=info["packets"], conversations=info["conversations"])
        if mode == "adaptive":
            rs = info["rs"]
            res["condition"] = "busy" if rs["status"] == "CONSTRAINED" else "free"
            res["forced"] = force != "none"
            res["cpu_reading"], res["mem_reading"] = rs.get("cpu_percent"), rs.get("memory_percent")
            res["cpu_total_reading"], res["cpu_own_reading"] = rs.get("cpu_total_percent"), rs.get("cpu_own_percent")
            res["model_loader"] = info.get("model_loader")
        res.update({k: round(v, 5) for k, v in ph.items()})
        res["total_s"], res["cpu_s"] = round(total, 5), round(cpu, 5)
        res["peak_mem_mb"] = peak_mb()
        res["work_mem_mb"] = round(res["peak_mem_mb"] - res["mem_after_imports_mb"], 1) if res["peak_mem_mb"] and res["mem_after_imports_mb"] else None
        s = enc.last_stats
        res["handshake_ms_total"], res["encrypt_ms_total"] = s["handshake_ms_total"], s["encrypt_ms_total"]
        res["crypto_core_s"] = round((s["handshake_ms_total"] + s["encrypt_ms_total"]) / 1000, 5)
        res["overhead_bytes"], res["flows"], res["checks"] = s["overhead_bytes"], s["flows"], s["checks"]
        e = pd.read_csv(os.path.join(tmp, "enc_a.csv"))
        first = e.groupby("Flow_Key", sort=False).first()
        kex = first["Key_Exchange_Used"].astype(str)
        kex_counts = kex.value_counts().to_dict()
        res["kex_labels"] = sorted(set(kex))
        res["quantum_safe_flows"] = [str(f) for f in first.index[kex.str.contains("ML-KEM|Kyber")]]
        res["pq_flow_share"] = round(len(res["quantum_safe_flows"]) / max(len(first), 1), 4)
        res["handshake_bytes"] = int(sum(hs_bytes(k) * v for k, v in kex_counts.items()))
        if mode == "adaptive":
            res["flow_levels"] = {str(f): str(l) for f, l in first["Sensitivity"].items()}
        cl = pd.to_numeric(e["Ciphertext_Length"], errors="coerce").fillna(0)
        res["applied"] = {
            "conversations": int(len(first)),
            "by_choice": (kex + " / " + first["Symmetric_Cipher"].astype(str)).value_counts().to_dict(),
            "packets_total": int(len(e)), "packets_encrypted": int((cl > 0).sum()), "packets_without_data": int((cl == 0).sum()),
            "payload_bytes": int(pd.to_numeric(e["Payload_Length"], errors="coerce").fillna(0).sum()), "ciphertext_bytes": int(cl.sum()),
        }
        res["ok"] = True

        # ---------------- second pass: the service is already running (model loaded, code warm) ----------------
        try:
            ph2, total2, cpu2, _enc2, _ = one_pass("b")
            res["steady_total_s"] = round(total2 - ph2["resource_read_s"], 5)       # the CPU-sampling wait is a background job in a service
            res["steady_decision_s"] = round(ph2["decision_s"], 5)
            res["steady_cpu_s"] = round(cpu2, 5)
        except Exception:
            pass

        # ---- is this run valid evidence? ----
        reasons = []
        if s["checks"]["tamper_missed"] or s["checks"]["roundtrip_fail"]:
            reasons.append("self-checks failed (decrypt or tamper)")
        if mode in ("static_pqc", "adaptive") and (res["provider"] != "liboqs" or any("DEV-SIM" in k for k in res["kex_labels"])):
            reasons.append("simulated ML-KEM was used, not real liboqs")
        if mode == "static_pqc" and res["pq_flow_share"] < 1.0:
            reasons.append("not every conversation used quantum-safe keys")
        res["valid"], res["invalid_reason"] = (not reasons), "; ".join(reasons) or None
    except Exception as ex:
        res["error"] = str(ex)[:300]
        res["traceback"] = traceback.format_exc()[-700:]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out(res)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["static_aes", "static_pqc", "adaptive"])
    ap.add_argument("--pcap", default="data/traffic.pcapng")
    ap.add_argument("--force", default="none", choices=["none", "AVAILABLE", "CONSTRAINED"])
    ap.add_argument("--micro", action="store_true")
    a = ap.parse_args()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if a.micro:
        micro()
    elif a.mode:
        run(a.mode, a.pcap, a.force)
    else:
        ap.error("give --mode or --micro")
