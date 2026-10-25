"""
Comparison Engine: measures the three encryption modes for real and keeps the evidence.

  A  static_aes : normal       = X25519 + AES-256-GCM for every conversation
  B  static_pqc : all quantum-safe = hybrid X25519 + ML-KEM-1024 for every conversation
  C  adaptive   : APQCrypt     = scoring + policy decide per conversation (uses the Settings)

Rules that make the numbers trustworthy:
  * a bar exists ONLY for a mode that was actually run (nothing is estimated or filled in);
  * every run is its own fresh process, on the same capture file, and is stored with evidence
    (time, machine, capture fingerprint, settings, self-check results);
  * the first run of each mode is a warm-up and is not counted;
  * runs that used simulated ML-KEM, or failed their self-checks, are stored but NOT counted;
  * results from another machine or another capture are never mixed in.
"""
import csv
import hashlib
import io
import json
import math
import os
import platform
import statistics as st
import subprocess
import sys
import threading
import time
import uuid

import config as cfgmod
import interfaces
import service

ROOT = "data/comparison"
RUNS_FILE = os.path.join(ROOT, "runs.jsonl")
MICRO_FILE = os.path.join(ROOT, "micro.jsonl")
PCAP = "data/traffic.pcapng"
WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "comparison_worker.py")
TIMEOUT_S = 3600
_file_lock = threading.Lock()
_state_lock = threading.Lock()
_proc = {"p": None}

MODES = {
    "static_aes": {"letter": "A", "title": "Normal", "label": "A · Normal (X25519 + AES-256-GCM)",
                   "about": "The usual approach today: the same classical key exchange and AES-256-GCM for every conversation. Not quantum-safe."},
    "static_pqc": {"letter": "B", "title": "All quantum-safe", "label": "B · All quantum-safe (hybrid ML-KEM-1024)",
                   "about": "Every conversation gets the hybrid X25519 + ML-KEM-1024 key exchange. The safest and most expensive option."},
    "adaptive": {"letter": "C", "title": "Adaptive (APQCrypt)", "label": "C · Adaptive (APQCrypt)",
                 "about": "Scores every conversation and the computer condition, then picks the protection. Uses the Settings page."},
}
METRICS = ["total_s", "cpu_s", "peak_mem_mb", "work_mem_mb", "parse_s", "decision_s", "model_load_s", "scoring_s", "resource_read_s", "policy_s",
           "encryption_total_s", "crypto_core_s", "handshake_ms_total", "encrypt_ms_total", "overhead_bytes", "pq_flow_share", "high_coverage", "import_s",
           "handshake_bytes", "steady_total_s", "steady_decision_s", "steady_cpu_s"]

STATE = {"running": False, "task": None, "plan": [], "done": 0, "total": 0, "current": None, "message": "", "error": None,
         "cancel": False, "started": None, "finished": None, "last_error": None}


# ------------------------------------------------------------------ environment facts
_host_cache = {}


def host_info():
    if _host_cache:
        return dict(_host_cache)
    info = {"machine": platform.machine(), "system": platform.system(), "python": platform.python_version(), "cores": os.cpu_count()}
    cpu = {}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if ":" in line:
                    k, v = [x.strip() for x in line.split(":", 1)]
                    cpu.setdefault(k.lower(), v)
                if not line.strip() and cpu:
                    break
    except OSError:
        pass
    info["cpu"] = cpu.get("model name") or cpu.get("uarch") or cpu.get("hardware") or platform.processor() or "unknown"
    info["isa"] = cpu.get("isa")
    try:
        with open("/proc/device-tree/model", "rb") as f:
            info["board"] = f.read().replace(b"\x00", b"").decode(errors="ignore").strip() or None
    except OSError:
        info["board"] = None
    try:
        with open("/proc/meminfo") as f:
            info["ram_gb"] = round(int(f.readline().split()[1]) / 1048576, 1)
    except (OSError, ValueError):
        info["ram_gb"] = None
    info["os"] = None
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    for name, mod in (("liboqs", "oqs"), ("cryptography", "cryptography"), ("scikit_learn", "sklearn")):
        try:
            m = __import__(mod)
            v = getattr(m, "oqs_version", None)
            info[name] = (v() if callable(v) else None) or getattr(m, "__version__", "installed")
        except Exception:
            info[name] = None
    key = "|".join(str(info.get(k)) for k in ("machine", "cpu", "cores", "ram_gb", "os", "board"))
    info["host_id"] = hashlib.sha1(key.encode()).hexdigest()[:8]
    info["label"] = f"{info['board'] or info['cpu']} · {info['machine']} · {info['cores']} cores" + (f" · {info['ram_gb']} GB" if info["ram_gb"] else "")
    _host_cache.update(info)
    return dict(info)


def pcap_fingerprint(path=PCAP):
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return {"path": path, "sha256": h.hexdigest(), "sha8": h.hexdigest()[:8], "size": os.path.getsize(path),
            "modified": os.path.getmtime(path)}


def _clean(v):
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return None
    return v


# ------------------------------------------------------------------ storage
def _append(path, rec):
    os.makedirs(ROOT, exist_ok=True)
    with _file_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")


def load_records(path=RUNS_FILE):
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def clear(mode=None, sha=None, host=None):
    """Delete stored runs (optionally only one mode, on one capture and machine)."""
    with _file_lock:
        recs = load_records()
        keep = [r for r in recs if not ((mode is None or r.get("mode") == mode) and (sha is None or r.get("capture_sha8") == sha)
                                         and (host is None or r.get("host_id") == host))]
        os.makedirs(ROOT, exist_ok=True)
        with open(RUNS_FILE, "w", encoding="utf-8") as f:
            for r in keep:
                f.write(json.dumps(r, default=str) + "\n")
    return len(recs) - len(keep)


# ------------------------------------------------------------------ running
def _spawn(args):
    proc = subprocess.Popen([sys.executable, WORKER] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=os.getcwd())
    _proc["p"] = proc
    try:
        so, se = proc.communicate(timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        so, se = proc.communicate()
        return None, "timed out after %d s" % TIMEOUT_S
    finally:
        _proc["p"] = None
    for line in reversed(so.splitlines()):
        if line.startswith("RESULT_JSON:"):
            try:
                return json.loads(line[len("RESULT_JSON:"):]), None
            except ValueError:
                break
    return None, ("worker produced no result. " + (se or so or "")[-300:]).strip()


def run_one(mode, fp, force, warmup):
    host = host_info()
    res, err = _spawn(["--mode", mode, "--pcap", fp["path"], "--force", force or "none"])
    rec = {"run_id": uuid.uuid4().hex[:10], "started_at": time.time(), "mode": mode, "warmup": bool(warmup),
           "host_id": host["host_id"], "host_label": host["label"], "capture_sha8": fp["sha8"], "capture_size": fp["size"],
           "config_sha": hashlib.sha1(json.dumps(cfgmod.get_all(), sort_keys=True).encode()).hexdigest()[:8]}
    if res is None:
        rec.update(ok=False, valid=False, error=err)
    else:
        rec.update(res)
    if mode == "adaptive" and rec.get("ok"):
        c = cfgmod.get_all()
        rec["config_used"] = {"resources": c["resources"], "high_threshold": c["scoring"]["high_threshold"],
                              "medium_threshold": c["scoring"]["medium_threshold"], "matrix": c["policy"]["matrix"]}
    _append(RUNS_FILE, rec)
    return rec


def _plan(modes, runs, interleave):
    plan = [(m, True) for m in modes]                              # one warm-up per mode, not counted
    if interleave:
        plan += [(m, False) for _ in range(runs) for m in modes]
    else:
        plan += [(m, False) for m in modes for _ in range(runs)]
    return plan


def preflight(modes):
    """Return an error message, or None if the modes can run now."""
    if not os.path.isfile(PCAP):
        return "No capture yet. Run the pipeline once (or use a capture file) so data/traffic.pcapng exists."
    if any(m in ("static_pqc", "adaptive") for m in modes):
        if interfaces.active_name("crypto_provider") != "liboqs":
            return "The crypto provider is 'simulated'. Quantum-safe modes must be measured with real liboqs. Change it on the Interfaces page."
        chk = interfaces.test("crypto_provider", "liboqs")
        if not chk or not chk["available"]:
            return "ML-KEM (liboqs) is not available: " + (chk["detail"] if chk else "unknown") + ". Install it first (see the guide)."
    if "adaptive" in modes:
        chk = interfaces.test("risk_model", "random_forest")
        if not chk or not chk["available"]:
            return "The AI model cannot be loaded: " + (chk["detail"] if chk else "unknown")
    return None


def start(modes, runs, force=None, interleave=True):
    """Start measuring in the background. The caller has already called service.try_start('comparison')."""
    fp = pcap_fingerprint()
    plan = _plan(modes, runs, interleave)
    with _state_lock:
        STATE.update(running=True, task="measure", plan=[{"mode": m, "warmup": w} for m, w in plan], done=0, total=len(plan), current=None,
                     message="Starting…", error=None, cancel=False, started=time.time(), finished=None, last_error=None)

    def loop():
        try:
            for i, (m, w) in enumerate(plan):
                if STATE["cancel"]:
                    STATE["message"] = "Cancelled"
                    break
                STATE["current"] = {"mode": m, "warmup": w, "index": i + 1}
                STATE["message"] = f"{MODES[m]['label']}: {'warm-up run (not counted)' if w else 'measured run'} {i + 1}/{len(plan)}"
                rec = run_one(m, fp, force if m == "adaptive" else None, w)
                STATE["done"] = i + 1
                if not rec.get("ok") or not rec.get("valid"):
                    STATE["last_error"] = f"{MODES[m]['title']}: " + (rec.get("error") or rec.get("invalid_reason") or "failed")
                    if not rec.get("ok"):                         # a hard failure: stop instead of repeating it
                        STATE["error"] = STATE["last_error"]
                        break
            else:
                STATE["message"] = "Finished"
        except Exception as e:
            STATE["error"] = str(e)[:300]
        finally:
            STATE.update(running=False, current=None, finished=time.time())
            service.finish()

    threading.Thread(target=loop, daemon=True).start()


def start_micro():
    with _state_lock:
        STATE.update(running=True, task="micro", plan=[], done=0, total=1, current={"mode": "micro"}, message="Measuring algorithm costs…",
                     error=None, cancel=False, started=time.time(), finished=None, last_error=None)

    def loop():
        try:
            res, err = _spawn(["--micro"])
            host = host_info()
            rec = {"run_id": uuid.uuid4().hex[:10], "started_at": time.time(), "host_id": host["host_id"], "host_label": host["label"]}
            if res is None:
                rec.update(ok=False, error=err)
                STATE["error"] = err
            else:
                rec.update(res)
                if not res.get("ok"):
                    STATE["error"] = res.get("error")
            _append(MICRO_FILE, rec)
            STATE["done"] = 1
            STATE["message"] = "Finished"
        except Exception as e:
            STATE["error"] = str(e)[:300]
        finally:
            STATE.update(running=False, current=None, finished=time.time())
            service.finish()

    threading.Thread(target=loop, daemon=True).start()


def cancel():
    STATE["cancel"] = True
    p = _proc["p"]
    if p:
        try:
            p.kill()
        except Exception:
            pass


# ------------------------------------------------------------------ summary
def _stats(vals):
    vals = [v for v in vals if isinstance(v, (int, float)) and not (isinstance(v, float) and (math.isnan(v) or math.isinf(v)))]
    if not vals:
        return None
    return {"n": len(vals), "mean": st.mean(vals), "std": st.stdev(vals) if len(vals) > 1 else None, "min": min(vals), "max": max(vals)}


def series_key(rec):
    return "adaptive:" + rec.get("condition", "free") if rec["mode"] == "adaptive" else rec["mode"]


def series_label(key):
    if key.startswith("adaptive:"):
        return "C · Adaptive (computer %s)" % key.split(":")[1]
    return MODES[key]["label"]


def summary(host=None, sha=None):
    me = host_info()
    fp = pcap_fingerprint()
    host = host or me["host_id"]
    sha = sha or (fp["sha8"] if fp else None)
    recs = load_records()
    all_hosts = {}
    all_caps = {}
    for r in recs:
        all_hosts[r.get("host_id")] = r.get("host_label")
        if r.get("host_id") == host:
            all_caps[r.get("capture_sha8")] = r.get("capture_size")
    here = [r for r in recs if r.get("host_id") == host and r.get("capture_sha8") == sha]

    # reference sensitivity levels (from the latest valid adaptive run) to judge protection of the HIGH conversations
    ref = next((r for r in reversed(here) if r["mode"] == "adaptive" and r.get("ok") and r.get("valid") and r.get("flow_levels")), None)
    high = {f for f, l in (ref or {}).get("flow_levels", {}).items() if l == "HIGH"}

    def coverage(r):
        if r["mode"] == "adaptive":
            hs = {f for f, l in (r.get("flow_levels") or {}).items() if l == "HIGH"}
        else:
            hs = high
        if not hs:
            return None
        return len(hs & set(r.get("quantum_safe_flows") or [])) / len(hs)

    counted = [r for r in here if r.get("ok") and r.get("valid") and not r.get("warmup")]
    groups = {}
    for r in counted:
        groups.setdefault(series_key(r), []).append(r)
    series = {}
    for key, rs in groups.items():
        row = {"key": key, "label": series_label(key), "mode": rs[0]["mode"], "n": len(rs),
               "last_run": max(r["started_at"] for r in rs), "packets": rs[-1].get("packets"), "conversations": rs[-1].get("conversations")}
        for m in METRICS:
            vals = [coverage(r) if m == "high_coverage" else r.get(m) for r in rs]
            row[m] = _stats(vals)
        row["kex_labels"] = sorted({k for r in rs for k in (r.get("kex_labels") or [])})
        row["applied"] = rs[-1].get("applied")
        row["model_loader"] = rs[-1].get("model_loader")
        series[key] = row

    modes_state = {}
    for m in MODES:
        mine = [r for r in here if r["mode"] == m]
        good = [r for r in counted if r["mode"] == m]
        bad = [r for r in mine if not r.get("warmup") and (not r.get("ok") or not r.get("valid"))]
        modes_state[m] = {**{k: MODES[m][k] for k in ("letter", "title", "label", "about")}, "runs_counted": len(good),
                          "last_run": max([r["started_at"] for r in good], default=None),
                          "last_problem": (bad[-1].get("error") or bad[-1].get("invalid_reason")) if bad else None,
                          "series": sorted({series_key(r) for r in good})}

    evidence = []
    for r in sorted(here, key=lambda x: x["started_at"], reverse=True)[:120]:
        evidence.append({k: _clean(r.get(k)) for k in ("run_id", "started_at", "mode", "condition", "forced", "warmup", "ok", "valid", "invalid_reason", "error",
                                                       "total_s", "cpu_s", "peak_mem_mb", "decision_s", "handshake_ms_total", "pq_flow_share", "packets", "conversations", "config_sha")})
    micro = [m for m in load_records(MICRO_FILE) if m.get("host_id") == host and m.get("ok")]
    return {
        "host": me, "capture": fp, "viewing": {"host": host, "sha": sha, "is_this_machine": host == me["host_id"],
                                                "is_current_capture": bool(fp and sha == fp["sha8"])},
        "datasets": {"hosts": [{"id": k, "label": v} for k, v in all_hosts.items()], "captures": [{"sha8": k, "size": v} for k, v in all_caps.items()]},
        "provider": interfaces.active_name("crypto_provider"), "modes": modes_state, "series": series, "messages": messages(series),
        "evidence": evidence, "micro": micro[-1] if micro else None, "state": dict(STATE),
        "reference_high_conversations": len(high), "ignored_runs": len(recs) - len(here),
    }


def _m(s, key, scale=1.0, nd=2):
    v = (s or {}).get(key)
    if not v:
        return None
    r = round(v["mean"] * scale, nd)
    return int(r) if nd == 0 else r


def messages(series):
    """Plain-language findings, written ONLY from measured numbers. They state bad news as clearly as good news."""
    A, B = series.get("static_aes"), series.get("static_pqc")
    C = series.get("adaptive:free") or series.get("adaptive:busy")
    out = []
    if not series:
        return ["Nothing has been measured yet. Press 'Measure' on a mode above."]
    if B and C:
        qa = (C.get("applied") or {}).get("by_choice", {})
        n_c = (C.get("applied") or {}).get("conversations")
        pq_c = sum(v for k, v in qa.items() if "ML-KEM" in k)
        qc, hc2 = _m(C, "pq_flow_share", 100, 0), _m(C, "high_coverage", 100, 0)
        out.append(f"Protection: adaptive made {qc}% of conversations quantum-safe ({pq_c} of {n_c})" + (f" and {hc2}% of the HIGH ones" if hc2 is not None else "")
                   + ", against 100% for mode B. Adaptive only saves quantum-safe work on the conversations it classifies as lower sensitivity.")
        bb, bc = _m(B, "handshake_bytes", 1 / 1024, 1), _m(C, "handshake_bytes", 1 / 1024, 1)
        if bb and bc is not None:
            out.append(f"Key-exchange data (computed from the published ML-KEM and X25519 sizes, so it does not vary between runs): adaptive {bc} KB, all quantum-safe {bb} KB"
                       + (f" ({round((1 - bc / bb) * 100)}% less)." if bc < bb else "."))
        hb, hc = _m(B, "handshake_ms_total"), _m(C, "handshake_ms_total")
        sb, sc = (B.get("handshake_ms_total") or {}).get("std"), (C.get("handshake_ms_total") or {}).get("std")
        if hb and hc is not None:
            noisy = (sb is not None and sb > 0.5 * hb) or (sc is not None and sc > 0.5 * hc)
            out.append(f"Key-exchange time: adaptive {hc} ms, all quantum-safe {hb} ms [{C['n']} and {B['n']} runs]."
                       + (" The runs vary a lot (spread above half of the average), so do NOT claim a percentage from this. Use more runs, or the key-exchange data above, which is exact." if noisy else ""))
    if A and C:
        ta, tc, dc = _m(A, "total_s", 1, 3), _m(C, "total_s", 1, 3), _m(C, "decision_s", 1, 3)
        rr = _m(C, "resource_read_s", 1, 2)
        if ta and tc:
            ml = _m(C, "model_load_s", 1, 3)
            out.append(f"First start, total time: adaptive {tc} s, normal {ta} s ({round(tc / ta, 1)}x). The decision (AI model load {ml} s, scoring, policy) is {dc} s of that"
                       + (f", plus {rr} s spent deliberately sampling the computer's load." if rr else "."))
        sa, sc2, sd = _m(A, "steady_total_s", 1, 3), _m(C, "steady_total_s", 1, 3), _m(C, "steady_decision_s", 1, 3)
        if sa is not None and sc2 is not None:
            out.append(f"Service already running (model loaded, second pass in the same process): adaptive {sc2} s, normal {sa} s. The decision costs {sd} s each time.")
        ma, mc = _m(A, "peak_mem_mb", 1, 0), _m(C, "peak_mem_mb", 1, 0)
        if ma and mc:
            out.append(f"Peak memory: normal {ma} MB, adaptive {mc} MB" + (f" (AI model loaded with: {C.get('model_loader')})." if C.get("model_loader") else "."))
    if B and C:
        hb, hc = _m(B, "handshake_ms_total"), _m(C, "handshake_ms_total")
        dc_ms = (_m(C, "decision_s", 1, 4) or 0) * 1000
        if hb is not None and hc is not None and dc_ms > max(hb - hc, 0):
            out.append(f"Honest note: on this machine the decision costs about {round(dc_ms)} ms, which is more than the key-exchange time saved against mode B ({round(max(hb - hc, 0), 1)} ms). "
                       "Adaptive does not save processing time here. What it saves is quantum-safe work and key-exchange data on lower-sensitivity conversations.")
    if A and B:
        ha, hb = _m(A, "handshake_ms_total"), _m(B, "handshake_ms_total")
        if ha is not None and hb is not None:
            out.append(f"Key exchange time over all conversations: normal (A) {ha} ms, all quantum-safe (B) {hb} ms.")
    thin = [s["label"] for s in series.values() if s["n"] < 3]
    if thin:
        out.append("Repeat these at least 3 times to get a reliable spread: " + "; ".join(thin) + ".")
    out.append("All modes are measured the same way: the same capture is replayed through each policy on this machine. This is processing cost, not live network delay.")
    return out


def evidence_csv():
    recs = load_records()
    cols = ["run_id", "started_at", "series", "mode", "condition", "forced", "warmup", "ok", "valid", "invalid_reason", "error", "host_label", "host_id",
            "capture_sha8", "packets", "conversations", "total_s", "parse_s", "decision_s", "model_load_s", "scoring_s", "resource_read_s", "policy_s",
            "encryption_total_s", "crypto_core_s", "handshake_ms_total", "handshake_bytes", "encrypt_ms_total", "cpu_s", "peak_mem_mb", "mem_after_imports_mb",
            "work_mem_mb", "steady_total_s", "steady_decision_s", "overhead_bytes", "flows", "pq_flow_share", "provider", "model_loader", "config_sha"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in recs:
        row = dict(r)
        row["series"] = series_label(series_key(r)) if r.get("mode") in MODES else ""
        row["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("started_at", 0)))
        w.writerow([row.get(c, "") for c in cols])
    return buf.getvalue()
