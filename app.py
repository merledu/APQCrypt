from flask import (Flask, render_template, jsonify, send_file, request, session,
                   redirect, url_for, abort, g)
import subprocess
import os
import math
import time
import pandas as pd
from status_manager import StatusManager
import threading
import json

import io
import zipfile
import inspect

import auth
import saved_runs

# Modules that come from the optimised-adaptive update. If one is missing, say so clearly.
try:
    import config as cfgmod
    import debuglog
    import interfaces
    import service
    import comparison
    from api_v1 import bp as api_v1_bp, get_key
except ImportError as _e:
    raise SystemExit(
        "\n[APQCrypt] A required module is missing: %s\n"
        "Copy config.py, debuglog.py, interfaces.py, service.py, comparison.py, comparison_worker.py,\n"
        "compact_model.py and api_v1.py from the optimised update into the project folder, then start again.\n" % _e)

app = Flask(__name__)
os.makedirs("data", exist_ok=True)
app.secret_key = auth.secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=1 * 1024 * 1024)
auth.install_gate(app)
app.register_blueprint(api_v1_bp)          # REST API: /api/v1/... (uses its own API key, not the login)

# ----- run state -----
# Only ONE of: pipeline run, comparison, API job at a time. service.py owns that lock.
pipeline_thread = None
last_run = {"user": None, "mode": None, "started": None}
STAGES = ["capture", "features", "sensitivity", "policy", "encryption"]
STAGE_INFO = [("capture", "Packet capture", "data/traffic.pcapng"), ("features", "Feature extraction", "data/features.csv"),
              ("sensitivity", "Sensitivity scoring", "data/results.csv"), ("policy", "Policy decision", "data/policy.csv"),
              ("encryption", "Encryption", "data/encrypted_results.csv")]


def pipeline_active():
    return service.current() == "pipeline"


network_state = {"ready": False, "message": "Not prepared", "updated": None}

# The five pipeline stages, shown side by side on every page: (key, label, url, short description)
NAV = [
    ("capture", "Capture", "/", "Packets and features"),
    ("sensitivity", "Sensitivity", "/sensitivity", "Risk scoring"),
    ("resources", "System condition", "/resources", "Resources and policy"),
    ("encryption", "Encryption", "/encryption", "Key exchange and ciphers"),
    ("compare", "Comparison", "/compare", "Adaptive vs static"),
]

# Interface bar (super admin only)
ADMIN_NAV = [
    ("debug", "Debug", "/admin/debug"),
    ("interface", "Interface", "/admin/interface"),
    ("settings", "Settings", "/admin/settings"),
    ("users", "Users", "/admin/users"),
]


@app.context_processor
def inject_globals():
    return {"nav": NAV, "admin_nav": ADMIN_NAV, "user": g.get("user"),
            "csrf_token": auth.csrf_token(), "settings": auth.get_settings()}


# ========== SMALL HELPERS ==========
def clean(v):
    """JSON cannot hold NaN. Turn NaN/inf into None so the browser can read it."""
    try:
        if v is None:
            return None
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            return None
        if hasattr(v, "item"):          # numpy scalar -> python
            v = v.item()
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                return None
        return v
    except Exception:
        return None


def df_records(df):
    """DataFrame rows as a list of dicts with NaN replaced by None."""
    recs = df.to_dict("records")
    return [{k: clean(v) for k, v in r.items()} for r in recs]


# ========== SAFETY CHECKS ==========
def check_sudo_access():
    try:
        result = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def check_mininet_installed():
    try:
        return subprocess.run(["which", "mn"], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def check_tshark_installed():
    try:
        return subprocess.run(["which", "tshark"], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def check_oqs():
    """True if liboqs has ML-KEM (or the older Kyber name)."""
    try:
        import oqs
        names = oqs.get_enabled_kem_mechanisms()
        return any(n in names for n in ("ML-KEM-1024", "Kyber1024"))
    except Exception:
        return False


def diagnostics_data():
    return {
        "sudo_access": check_sudo_access(),
        "mininet_installed": check_mininet_installed(),
        "tshark_installed": check_tshark_installed(),
        "liboqs_mlkem": check_oqs(),
        "data_dir_exists": os.path.isdir("data"),
    }


# ========== PAGES ==========
@app.route("/")
def page_capture():
    return render_template("capture.html", page="capture")


@app.route("/sensitivity")
def page_sensitivity():
    return render_template("sensitivity.html", page="sensitivity")


@app.route("/resources")
def page_resources():
    return render_template("resources.html", page="resources")


@app.route("/encryption")
def page_encryption():
    return render_template("encryption.html", page="encryption")


@app.route("/compare")
def page_compare():
    return render_template("compare.html", page="compare")


# ========== START PIPELINE ==========
def effective_force(requested=None):
    """System-load simulation is a super-admin tool.
    1) A load source pinned in Settings applies to everyone.
    2) Otherwise a super admin may ask for one run to be simulated.
    3) Everybody else always gets the real, measured load."""
    pinned = auth.get_settings()["load_source"]
    if pinned in ("AVAILABLE", "CONSTRAINED"):
        return pinned
    if requested in ("AVAILABLE", "CONSTRAINED") and g.get("user") and g.user["role"] == "super_admin":
        return requested
    return None


@app.route("/start-pipeline", methods=["POST"])
def start_pipeline():
    global pipeline_thread

    mode = request.args.get("mode") or auth.get_settings()["default_mode"]
    if mode not in auth.MODES:
        mode = "adaptive"
    force = effective_force(request.args.get("force"))
    stop_after = request.args.get("stop_after")
    start_from = request.args.get("start_from")
    if stop_after not in STAGES:
        stop_after = None
    if start_from not in STAGES:
        start_from = None
    start_idx = STAGES.index(start_from) if start_from else 0
    if stop_after and STAGES.index(stop_after) < start_idx:
        return {"message": "'Stop after' comes before 'Start from'.", "status": "error"}, 400
    replay = "data/traffic.pcapng" if request.args.get("replay") == "1" else None

    if replay and not os.path.exists(replay):
        return {"message": "There is no previous capture to reuse. Clear the \"Reuse last capture\" option.", "status": "error"}, 400
    if start_idx > 0:
        missing = [info[2] for info in STAGE_INFO[:start_idx] if not os.path.exists(info[2])]
        if missing:
            return {"message": f"Cannot start from '{start_from}': missing {', '.join(missing)}. Run the full pipeline first.", "status": "error"}, 400
    needs_capture = start_idx == 0 and not replay and interfaces.active_name("packet_source") == "mininet"
    if needs_capture:
        if not check_sudo_access():
            return {"message": "Capture needs passwordless sudo, which is not available on this machine.", "status": "error"}, 403
        if not check_mininet_installed():
            return {"message": "Mininet is not installed on this machine.", "status": "error"}, 400
        if not check_tshark_installed():
            return {"message": "tshark is not installed on this machine.", "status": "error"}, 400

    if not service.try_start("pipeline"):
        return {"message": f"'{service.current()}' is already running. Wait for it to finish.", "status": "busy"}, 409

    last_run.update(user=g.user["username"], mode=mode, started=time.time())
    auth.audit("pipeline_start", f"mode={mode} replay={bool(replay)} load={force or 'real'}")

    # Reset the status file NOW so the page never reads the previous run's "Finished".
    StatusManager.update_status("Starting", f"Pipeline starting ({mode})...", 0)

    def run_pipeline():
        from main_controller import PipelineController
        try:
            ctl = PipelineController()
            kwargs = dict(mode=mode, replay_pcap=replay, force_resource=force, stop_after=stop_after, start_from=start_from)
            accepted = inspect.signature(ctl.run).parameters          # pass only what this controller supports
            ctl.run(**{k: v for k, v in kwargs.items() if k in accepted})
        except Exception as e:
            import traceback
            traceback.print_exc()
            StatusManager.update_status("Error", f"Pipeline failed: {str(e)}")
        finally:
            service.finish()

    pipeline_thread = threading.Thread(target=run_pipeline, daemon=True)
    pipeline_thread.start()
    return {"message": "Pipeline started", "status": "running"}


# ========== STATUS ==========
@app.route("/status")
def status():
    try:
        return jsonify(StatusManager.get_status())
    except Exception as e:
        print(f"Status error: {e}")
        return jsonify({"stage": "Idle", "message": "No status available", "progress": 0})


def _has_comparison_runs():
    p = "data/comparison/runs.jsonl"
    try:
        return os.path.exists(p) and os.path.getsize(p) > 0
    except OSError:
        return False


@app.route("/api/state")
def api_state():
    """Everything the stage bar needs in one call."""
    try:
        st = StatusManager.get_status()
    except Exception:
        st = {"stage": "Idle", "message": "", "progress": 0}
    cs = getattr(comparison, "STATE", {}) or {}
    return jsonify({
        "status": st,
        "pipeline_running": pipeline_active(),
        "busy_with": service.current(),
        "run_by": last_run["user"],
        "bench": {"running": bool(cs.get("running")) or service.current() == "comparison",
                  "error": cs.get("error"), "message": cs.get("message", "")},
        "has_results": saved_runs.has_results(),
        "has_benchmark": _has_comparison_runs(),
        "default_mode": auth.get_settings()["default_mode"],
    })


# ========== RESULTS (summary numbers for all pages) ==========
@app.route("/results")
def results():
    data = {
        "features": [], "protocols": {}, "sensitivity": {}, "risk_tiers": {}, "policies": {},
        "algorithms": {}, "key_exchanges": {}, "resource_status": None, "total_packets": 0,
        "flows": None, "packets_with_payload": None, "dpi_found": None,
        "packet_file": None, "feature_file": None, "result_file": None, "policy_file": None,
        "encrypted_file": None, "encryption_summary": {}, "encryption_checks": None,
        "module_timings": {}, "total_time": 0
    }

    if os.path.exists("data/traffic.pcapng"):
        try:
            data["packet_file"] = f"data/traffic.pcapng ({os.path.getsize('data/traffic.pcapng')} bytes)"
        except Exception:
            data["packet_file"] = "data/traffic.pcapng"

    if os.path.exists("data/features.csv"):
        data["feature_file"] = "data/features.csv"
        try:
            df = pd.read_csv("data/features.csv")
            data["features"] = list(df.columns)
            data["total_packets"] = int(len(df))
            if "Protocol" in df.columns:
                data["protocols"] = {k: int(v) for k, v in df["Protocol"].value_counts().items()}
            if "Flow_ID" in df.columns:
                data["flows"] = int(df["Flow_ID"].nunique())
            if "Payload_Len" in df.columns:
                data["packets_with_payload"] = int((df["Payload_Len"] > 0).sum())
        except Exception as e:
            print(f"Feature file read error: {e}")

    if os.path.exists("data/results.csv"):
        data["result_file"] = "data/results.csv"
        try:
            rdf = pd.read_csv("data/results.csv")
            if "Sensitivity" in rdf.columns:
                data["sensitivity"] = {k: int(v) for k, v in rdf["Sensitivity"].value_counts().items()}
            if "Risk_Tier" in rdf.columns:
                data["risk_tiers"] = {k: int(v) for k, v in rdf["Risk_Tier"].value_counts().items()}
            if "DPI_Signal" in rdf.columns:
                data["dpi_found"] = int(rdf["DPI_Signal"].notna().sum())
        except Exception as e:
            print(f"Results file read error: {e}")

    if os.path.exists("data/policy.csv"):
        data["policy_file"] = "data/policy.csv"
        try:
            pdf = pd.read_csv("data/policy.csv")
            if "Selected_Policy" in pdf.columns:
                data["policies"] = {k: int(v) for k, v in pdf["Selected_Policy"].value_counts().items()}
            if "Selected_Algorithm" in pdf.columns:
                data["algorithms"] = {k: int(v) for k, v in pdf["Selected_Algorithm"].value_counts().items()}
            if "Key_Exchange" in pdf.columns:
                data["key_exchanges"] = {k: int(v) for k, v in pdf["Key_Exchange"].value_counts().items()}
            if "Resource_Status" in pdf.columns and len(pdf) > 0:
                data["resource_status"] = {
                    "status": clean(pdf["Resource_Status"].iloc[0]),
                    "cpu_percent": clean(pdf["CPU_Percent"].iloc[0]) if "CPU_Percent" in pdf.columns else None,
                    "memory_percent": clean(pdf["Memory_Percent"].iloc[0]) if "Memory_Percent" in pdf.columns else None,
                }
        except Exception as e:
            print(f"Policy file read error: {e}")

    if os.path.exists("data/encrypted_results.csv"):
        data["encrypted_file"] = "data/encrypted_results.csv"
        try:
            edf = pd.read_csv("data/encrypted_results.csv")
            handshakes = edf[edf["New_Flow_Handshake"] == True]
            pqc_handshakes = handshakes[handshakes["PQC_Handshake_Used"] == True]
            data["encryption_summary"] = {
                "total_packets": int(len(edf)),
                "total_flows": int(handshakes.shape[0]),
                "pqc_handshakes": int(pqc_handshakes.shape[0]),
                "total_handshake_ms": round(float(handshakes["Handshake_Time_ms"].sum()), 3),
                "total_encrypt_ms": round(float(edf["Encrypt_Time_us"].sum()) / 1000, 3),
                "total_ciphertext_bytes": int(edf["Ciphertext_Length"].sum()),
            }
        except Exception as e:
            print(f"Encrypted results read error: {e}")

    if os.path.exists("data/encryption_checks.json"):
        try:
            with open("data/encryption_checks.json") as f:
                data["encryption_checks"] = json.load(f)
        except Exception:
            pass

    if os.path.exists("data/timings.json"):
        try:
            with open("data/timings.json") as f:
                timings = json.load(f)
                data["module_timings"] = timings.get("modules", {})
                data["total_time"] = timings.get("total", 0)
        except Exception as e:
            print(f"Timings read error: {e}")

    return jsonify(data)


# ========== ONE ROW PER CONVERSATION ==========
@app.route("/flows")
def flows():
    p = "data/encrypted_results.csv"
    if not os.path.exists(p):
        return {"rows": []}
    try:
        df = pd.read_csv(p)
        rows = []
        for fk, d in df.groupby("Flow_Key", sort=False):
            first = d.iloc[0]
            dpi = d["DPI_Signal"].dropna().astype(str) if "DPI_Signal" in d.columns else []
            rows.append({
                "flow": str(fk),
                "protocol": str(first.get("Protocol", "")),
                "packets": int(len(d)),
                "sensitivity": str(first.get("Sensitivity", "")),
                "score": clean(first.get("Final_Score")),
                "peek": dpi.iloc[0] if len(dpi) else "",
                "key_exchange": str(first.get("Key_Exchange_Used", "")),
                "cipher": str(first.get("Symmetric_Cipher", "")),
                "handshake_ms": round(float(pd.to_numeric(d["Handshake_Time_ms"], errors="coerce").sum()), 3),
                "reason": str(first.get("Reason", "")),
            })
        return jsonify({"rows": rows})
    except Exception as e:
        return {"rows": [], "error": str(e)}, 500


# ========== LIVE COMPUTER CONDITION + DECISION TABLE ==========
@app.route("/live-resources")
def live_resources():
    try:
        import psutil
        from policy_engine import get_limits
        C, M, _ = get_limits()
        cpu = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory().percent
        return jsonify({"cpu": cpu, "memory": mem, "cpu_limit": C, "memory_limit": M,
                        "status": "CONSTRAINED" if (cpu >= C or mem >= M) else "AVAILABLE"})
    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/policy-matrix")
def policy_matrix():
    try:
        from policy_engine import get_decision_matrix, get_limits
        C, M, _ = get_limits()
        rows = [{"sensitivity": s_, "resources": r, "algorithm": d["algorithm"], "kex": d["kex"],
                 "cipher": d["symmetric_cipher"], "policy": d["policy"],
                 "pqc_handshake": d["kex"].startswith("HYBRID")} for (s_, r), d in get_decision_matrix().items()]
        return jsonify({"rows": rows, "cpu_limit": C, "mem_limit": M})
    except Exception as e:
        return {"error": str(e)}, 500


# ========== COMPARISON ENGINE (measured runs + evidence) ==========
@app.route("/api/comparison")
def api_comparison():
    return jsonify(comparison.summary(request.args.get("host") or None, request.args.get("sha") or None))


@app.route("/api/comparison/status")
def api_comparison_status():
    return jsonify(comparison.STATE)


@app.route("/api/comparison/run", methods=["POST"])
def api_comparison_run():
    b = request.get_json(silent=True) or {}
    modes = b.get("modes")
    if not isinstance(modes, list) or not modes or any(m not in comparison.MODES for m in modes):
        return {"message": "Choose at least one mode: static_aes, static_pqc, adaptive."}, 400
    modes = [m for m in comparison.MODES if m in modes]                    # fixed order, no duplicates
    try:
        runs = int(b.get("runs", 3))
    except (TypeError, ValueError):
        runs = 3
    if not 1 <= runs <= 15:
        return {"message": "Runs per mode must be between 1 and 15."}, 400
    force = effective_force(b.get("force"))
    problem = comparison.preflight(modes)
    if problem:
        return {"message": problem}, 400
    if not service.try_start("comparison"):
        return {"message": f"'{service.current()}' is already running. Wait for it to finish."}, 409
    auth.audit("comparison_start", f"modes={','.join(modes)} runs={runs} load={force or 'real'}")
    comparison.start(modes, runs, force, bool(b.get("interleave", True)))
    return {"ok": True, "message": "Measuring started", "total_runs": len(modes) * (runs + 1)}


@app.route("/api/comparison/micro", methods=["POST"])
def api_comparison_micro():
    if not service.try_start("comparison"):
        return {"message": f"'{service.current()}' is already running. Wait for it to finish."}, 409
    auth.audit("comparison_micro")
    comparison.start_micro()
    return {"ok": True}


@app.route("/api/comparison/cancel", methods=["POST"])
def api_comparison_cancel():
    auth.audit("comparison_cancel")
    comparison.cancel()
    return {"ok": True}


@app.route("/api/comparison/clear", methods=["POST"])
@auth.admin_required
def api_comparison_clear():
    if comparison.STATE["running"]:
        return {"message": "Wait for the running measurement to finish."}, 409
    b = request.get_json(silent=True) or {}
    me = comparison.host_info()["host_id"]
    fp = comparison.pcap_fingerprint()
    if b.get("all"):
        n = comparison.clear()
    else:
        mode = b.get("mode")
        if mode not in comparison.MODES:
            return {"message": "unknown mode"}, 400
        n = comparison.clear(mode, fp["sha8"] if fp else None, me)
    auth.audit("comparison_clear", "all" if b.get("all") else b.get("mode"))
    return {"ok": True, "removed": n}


@app.route("/api/comparison/export.csv")
def api_comparison_export():
    return send_file(io.BytesIO(comparison.evidence_csv().encode("utf-8")), mimetype="text/csv", as_attachment=True,
                     download_name="apqcrypt_comparison_evidence.csv")


# ========== CONFIGURATION / CONNECTIONS / DEBUG APIs (super admin only) ==========
@app.route("/api/config", methods=["GET", "PUT"])
@auth.admin_required
def api_config():
    if request.method == "PUT":
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("config"), dict):
            return {"errors": ["send JSON like {\"config\": {...}}"]}, 400
        try:
            saved = cfgmod.save(body["config"], merge=True)
        except cfgmod.ConfigError as e:
            return {"errors": e.errors}, 400
        auth.audit("config_changed")
        return {"ok": True, "config": saved}
    return jsonify({"config": cfgmod.get_all(), "defaults": cfgmod.DEFAULTS, "presets": cfgmod.preset_list(),
                    "choices": {"kex": cfgmod.KEX_CHOICES, "cipher": cfgmod.CIPHER_CHOICES, "protocols": cfgmod.PROTOCOLS,
                                "packet_sources": cfgmod.PACKET_SOURCES, "crypto_providers": cfgmod.CRYPTO_PROVIDERS},
                    "saved": os.path.exists(cfgmod.CONFIG_FILE)})


@app.route("/api/config/reset", methods=["POST"])
@auth.admin_required
def api_config_reset():
    auth.audit("config_reset")
    return {"ok": True, "config": cfgmod.reset()}


@app.route("/api/config/preset/<name>", methods=["POST"])
@auth.admin_required
def api_config_preset(name):
    try:
        cfg = cfgmod.apply_preset(name)
    except cfgmod.ConfigError as e:
        return {"errors": e.errors}, 400
    auth.audit("config_preset", name)
    return {"ok": True, "config": cfg}


@app.route("/api/config/export")
@auth.admin_required
def api_config_export():
    data = json.dumps(cfgmod.get_all(), indent=2).encode()
    return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True, download_name="apqcrypt_config.json")


@app.route("/api/interfaces")
@auth.admin_required
def api_interfaces():
    return jsonify({"rows": interfaces.health(), "base_url": request.host_url.rstrip("/") + "/api/v1"})


@app.route("/api/interfaces/test", methods=["POST"])
@auth.admin_required
def api_interfaces_test():
    b = request.get_json(silent=True) or {}
    res = interfaces.test(b.get("kind"), b.get("name"))
    return (jsonify(res), 200) if res else ({"error": "unknown connection"}, 404)


@app.route("/api/interfaces/select", methods=["POST"])
@auth.admin_required
def api_interfaces_select():
    b = request.get_json(silent=True) or {}
    kind, name = b.get("kind"), b.get("name")
    if kind not in ("packet_source", "crypto_provider") or name not in interfaces.REGISTRY.get(kind, {}):
        return {"error": "unknown connection"}, 400
    if kind == "crypto_provider" and name == "simulated" and not b.get("confirm_unsafe"):
        return {"error": "the simulated provider is NOT quantum-safe. Confirm to use it for development only."}, 400
    try:
        cfgmod.save({"interfaces": {kind: name}}, merge=True)
    except cfgmod.ConfigError as e:
        return {"errors": e.errors}, 400
    auth.audit("interface_selected", f"{kind}={name}")
    return {"ok": True, "active": interfaces.active_name(kind)}


def _csv_rows(path):
    try:
        with open(path, "rb") as f:
            return max(sum(1 for _ in f) - 1, 0)
    except OSError:
        return None


@app.route("/api/debug/events")
@auth.admin_required
def api_debug_events():
    try:
        since = int(request.args.get("since", 0))
        limit = min(int(request.args.get("limit", 300)), 1000)
    except ValueError:
        since, limit = 0, 300
    ev = debuglog.read(since, request.args.get("stage") or None, request.args.get("level") or None, limit)
    tail = debuglog.read(0, limit=1)
    return jsonify({"events": ev, "last_seq": ev[-1]["seq"] if ev else since, "max_seq": tail[-1]["seq"] if tail else 0})


@app.route("/api/debug/stages")
@auth.admin_required
def api_debug_stages():
    events = debuglog.read(0, limit=1000)
    run_start = max([e["seq"] for e in events if e["stage"] == "pipeline" and e["msg"] == "run_start"] or [0])
    out = []
    for key, title, path in STAGE_INFO:
        ev = [e for e in events if e["stage"] == key]
        start = next((e for e in reversed(ev) if e["msg"] == "stage_start"), None)
        end = next((e for e in reversed(ev) if e["msg"] == "stage_end"), None)
        error = next((e for e in reversed(ev) if e["level"] == "error"), None)
        warns = [e["msg"] for e in ev if e["level"] == "warn"]
        exists = os.path.exists(path)
        if error and (not end or error["seq"] > end["seq"]):
            status = "error"
        elif end:
            status = "done"
        elif start:
            status = "running"
        else:
            status = "not run" if not exists else "files only"
        out.append({"stage": key, "title": title, "status": status, "output": path, "exists": exists,
                    "size": os.path.getsize(path) if exists else None, "rows": _csv_rows(path) if path.endswith(".csv") else None,
                    "params": (start or {}).get("data", {}).get("params"), "result": (end or {}).get("data"),
                    "seconds": (end or {}).get("data", {}).get("seconds"), "error": (error or {}).get("data"),
                    "error_msg": (error or {}).get("msg"), "warnings": warns})
    return jsonify({"stages": out, "run_started_seq": run_start})


def _first(df, col, default=None):
    return df[col].iloc[0] if (col in df.columns and len(df)) else default


@app.route("/api/debug/trace")
@auth.admin_required
def api_debug_trace():
    flow = request.args.get("flow", "")
    src = next((p for p in ("data/encrypted_results.csv", "data/policy.csv", "data/results.csv") if os.path.exists(p)), None)
    if not src:
        return {"error": "No results yet. Run the pipeline first."}, 404
    df = pd.read_csv(src)
    key = "Flow_Key" if "Flow_Key" in df.columns else "Flow_ID"
    rows = df[df[key].astype(str) == flow]
    if rows.empty:
        return {"error": "Conversation not found. Pick one from the list."}, 404
    feats = pd.read_csv("data/features.csv") if os.path.exists("data/features.csv") else None
    f = feats[feats["Flow_ID"].astype(str) == flow] if feats is not None and "Flow_ID" in feats.columns else None
    S = cfgmod.get("scoring")
    steps = []

    if f is not None and len(f):
        ts = pd.to_numeric(f.get("Timestamp"), errors="coerce")
        steps.append({"step": 1, "title": "Capture", "summary": f"{len(f)} packets recorded for this conversation",
                      "details": {"packets": int(len(f)), "first_packet_number": int(f["Pkt_Index"].min()), "last_packet_number": int(f["Pkt_Index"].max()),
                                  "duration_seconds": round(float(ts.max() - ts.min()), 4) if ts.notna().any() else None}})
        pay = f[pd.to_numeric(f["Payload_Len"], errors="coerce") > 0]
        hexs = str(pay["First_Bytes_Hex"].iloc[0]) if len(pay) and "First_Bytes_Hex" in pay.columns else ""
        raw = bytes.fromhex(hexs[:96]) if hexs and len(hexs[:96]) % 2 == 0 else b""
        steps.append({"step": 2, "title": "Features", "summary": f"{_first(f, 'Protocol')} · ports {int(_first(f, 'Source_Port', 0))} → {int(_first(f, 'Dest_Port', 0))} · {len(pay)} packet(s) carry data",
                      "details": {"protocol": _first(f, "Protocol"), "source_port": int(_first(f, "Source_Port", 0)), "dest_port": int(_first(f, "Dest_Port", 0)),
                                  "packets_with_data": int(len(pay)), "tcp_flags_first_8": [str(x) for x in f["TCP_Flags"].fillna("").head(8)] if "TCP_Flags" in f.columns else None,
                                  "first_data_bytes_hex": hexs[:96] or None,
                                  "first_data_bytes_text": "".join(chr(b) if 32 <= b < 127 else "." for b in raw) or None}})
    peek = [str(x) for x in rows["DPI_Signal"].dropna().unique()] if "DPI_Signal" in rows.columns else []
    steps.append({"step": 3, "title": "Rule score (port + protocol + peek)",
                  "summary": f"rule score {rows['Confidentiality_Score'].max()} from {_first(rows, 'Confidentiality_Signal')}" + (f"; peek found: {', '.join(peek[:3])}" if peek else "; no plain-text clue found"),
                  "details": {"confidentiality_score_max": float(rows["Confidentiality_Score"].max()), "signal": _first(rows, "Confidentiality_Signal"), "peek_clues": peek,
                              "peek_enabled": S["use_peek"]}})
    conf = pd.to_numeric(rows["Risk_Confidence"], errors="coerce")
    tiers = {k: int(v) for k, v in rows["Risk_Tier"].value_counts().items()}
    avg_conf = None if conf.notna().sum() == 0 else round(float(conf.mean()), 3)
    steps.append({"step": 4, "title": "AI behaviour risk (Random Forest)",
                  "summary": (f"AI said {tiers} (average confidence {avg_conf})" if avg_conf is not None
                              else f"The AI was not needed for this conversation: {tiers} (the rules had already decided HIGH)"),
                  "details": {"risk_tiers": tiers, "average_confidence": avg_conf,
                              "unsure_packets": int((conf < S["uncertain_confidence"]).sum()), "unsure_below": S["uncertain_confidence"],
                              "unsure_rule": "raise to MEDIUM" if S["raise_when_uncertain"] else "ignore",
                              "note": "only the first N packets of a conversation are scored; the AI is skipped when the rule score is already HIGH"}})
    steps.append({"step": 5, "title": "Combine (MAX) and decide the level",
                  "summary": f"final score {float(rows['Final_Score'].max())} → {_first(rows, 'Sensitivity')}",
                  "details": {"best_packet_score": float(rows["Packet_Score"].max()), "final_score": float(rows["Final_Score"].max()),
                              "sensitivity": _first(rows, "Sensitivity"), "high_threshold": S["high_threshold"], "medium_threshold": S["medium_threshold"],
                              "first_n_packets_used": S["flow_first_n"], "reason": _first(rows, "Reason")}})
    if "Selected_Algorithm" in rows.columns:
        steps.append({"step": 6, "title": "Policy (decision table)", "summary": f"{_first(rows, 'Sensitivity')} + {_first(rows, 'Resource_Status')} → {_first(rows, 'Selected_Algorithm')}",
                      "details": {"mode": _first(rows, "Mode"), "computer_condition": _first(rows, "Resource_Status"),
                                  "cpu_other_programs_percent": None if pd.isna(_first(rows, "CPU_Percent")) else _first(rows, "CPU_Percent"),
                                  "memory_other_programs_percent": None if pd.isna(_first(rows, "Memory_Percent")) else _first(rows, "Memory_Percent"),
                                  "algorithm": _first(rows, "Selected_Algorithm"), "key_exchange": _first(rows, "Key_Exchange"),
                                  "cipher": _first(rows, "Symmetric_Cipher"), "why": _first(rows, "Policy_Reason")}})
    if "Key_Exchange_Used" in rows.columns:
        hs = pd.to_numeric(rows["Handshake_Time_ms"], errors="coerce").sum()
        steps.append({"step": 7, "title": "Key exchange", "summary": f"{_first(rows, 'Key_Exchange_Used')} in {round(float(hs), 3)} ms (once for the whole conversation)",
                      "details": {"key_exchange_used": _first(rows, "Key_Exchange_Used"), "time_ms": round(float(hs), 3),
                                  "note": "both sides are simulated in one program"}})
        pl = pd.to_numeric(rows["Payload_Length"], errors="coerce").fillna(0)
        cl = pd.to_numeric(rows["Ciphertext_Length"], errors="coerce").fillna(0)
        us = pd.to_numeric(rows["Encrypt_Time_us"], errors="coerce").fillna(0)
        checks = None
        try:
            with open("data/encryption_checks.json") as fh:
                checks = json.load(fh).get("checks")
        except (OSError, ValueError):
            pass
        steps.append({"step": 8, "title": "Encryption and checks", "summary": f"{int((cl > 0).sum())} packet(s) encrypted · {int(pl.sum())} data bytes → {int(cl.sum())} bytes · {round(float(us.sum()), 1)} µs",
                      "details": {"packets_encrypted": int((cl > 0).sum()), "data_bytes": int(pl.sum()), "ciphertext_bytes": int(cl.sum()),
                                  "overhead_bytes": int(cl.sum() - pl.sum()), "encrypt_time_us": round(float(us.sum()), 1),
                                  "self_checks_whole_run": checks}})
    return jsonify({"flow": flow, "source_file": src, "steps": steps})


@app.route("/api/debug/run-config")
@auth.admin_required
def api_debug_run_config():
    try:
        with open("data/run_config.json") as f:
            return jsonify(json.load(f))
    except (OSError, ValueError):
        return {"error": "no run yet"}, 404


@app.route("/api/debug/bundle")
@auth.admin_required
def api_debug_bundle():
    files = ["data/run_config.json", "data/config.json", "data/debug_events.jsonl", "data/timings.json", "data/status.json",
             "data/encryption_checks.json", "data/features.csv", "data/results.csv", "data/policy.csv", "data/encrypted_results.csv",
             "data/comparison/runs.jsonl", "data/comparison/micro.jsonl"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            if os.path.exists(p):
                z.write(p, os.path.basename(p))
        pcap = "data/traffic.pcapng"
        if os.path.exists(pcap) and os.path.getsize(pcap) <= 5_000_000:
            z.write(pcap, "traffic.pcapng")
    buf.seek(0)
    auth.audit("debug_bundle_downloaded")
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name="apqcrypt_debug_bundle.zip")


# ========== FILE DOWNLOAD / VIEW ==========
@app.route("/download/<file_type>")
def download_file(file_type):
    file_map = {
        "packets": "data/traffic.pcapng",
        "features": "data/features.csv",
        "results": "data/results.csv",
        "policy": "data/policy.csv",
        "encrypted": "data/encrypted_results.csv",
        "benchmark": "data/benchmark_summary.csv",
    }
    file_path = file_map.get(file_type)
    if file_path and os.path.exists(file_path):
        try:
            return send_file(file_path, as_attachment=True)
        except Exception as e:
            return {"error": f"Download failed: {str(e)}"}, 500
    return {"error": "File not found"}, 404


@app.route("/view/<file_type>")
def view_file(file_type):
    file_map = {
        "features": "data/features.csv",
        "results": "data/results.csv",
        "policy": "data/policy.csv",
        "encrypted": "data/encrypted_results.csv",
    }
    file_path = file_map.get(file_type)
    if file_path and os.path.exists(file_path):
        try:
            df = pd.read_csv(file_path)
            return jsonify({"columns": list(df.columns), "data": df_records(df.head(50)), "total_rows": int(len(df))})
        except Exception as e:
            return {"error": f"File read error: {str(e)}"}, 500
    return {"error": "File not found"}, 404


# ========== SIGN IN / SIGN OUT / FIRST-RUN SETUP ==========
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if auth.has_users():
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        if pw != pw2:
            error = "The two passwords do not match."
        else:
            u, error = auth.create_user(request.form.get("username", "").strip(), pw, "super_admin",
                                        request.form.get("display_name", ""), signed_in=True)
            if u:
                session.clear()
                session["user"] = u["username"]
                session.permanent = True
                auth.audit("setup", "first super admin created", user=u["username"])
                return redirect(url_for("page_capture"))
    return render_template("setup.html", page="setup", error=error, min_password=auth.MIN_PASSWORD)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = auth.safe_next(request.values.get("next"))
    if request.method == "POST":
        name, error = auth.authenticate(request.form.get("username", "").strip(), request.form.get("password", ""))
        if name:
            token = session.get("csrf")
            session.clear()                      # new session on every sign-in
            session["csrf"] = token
            session["user"] = name
            session.permanent = True
            auth.audit("login", "", user=name)
            return redirect(nxt or url_for("page_capture"))
    return render_template("login.html", page="login", error=error, next=nxt or "")


@app.route("/logout", methods=["POST"])
def logout():
    auth.audit("logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
def account():
    msg = error = None
    if request.method == "POST":
        u = auth.get_user(g.user["username"])
        from werkzeug.security import check_password_hash
        new, new2 = request.form.get("new_password", ""), request.form.get("confirm", "")
        if not check_password_hash(u["password_hash"], request.form.get("current_password", "")):
            error = "The current password is not correct."
        elif new != new2:
            error = "The two new passwords do not match."
        else:
            _, error = auth.update_user(g.user["username"], {"password": new}, g.user["username"])
            if not error:
                auth.audit("password_changed")
                msg = "Password updated."
    return render_template("account.html", page="account", msg=msg, error=error, min_password=auth.MIN_PASSWORD)


# ========== SAVED RESULTS (every signed-in user) ==========
def _can_see_run(meta):
    return bool(meta) and (g.user["role"] == "super_admin" or meta.get("owner") == g.user["username"])


@app.route("/saved")
def page_saved():
    return render_template("saved.html", page="saved")


@app.route("/saved/<rid>")
def page_saved_run(rid):
    meta = saved_runs.get_run(rid)
    if not _can_see_run(meta):
        abort(404)
    return render_template("saved_run.html", page="saved_run", run=meta)


@app.route("/api/runs", methods=["GET"])
def api_runs():
    owner = None if g.user["role"] == "super_admin" else g.user["username"]
    return jsonify({"rows": saved_runs.list_runs(owner), "all_users": owner is None})


@app.route("/api/runs", methods=["POST"])
def api_runs_save():
    if service.current():
        return {"message": "Wait for the current run to finish before saving.", "status": "busy"}, 409
    body = request.get_json(silent=True) or {}
    meta, err = saved_runs.save_current(body.get("name"), g.user["username"])
    if err:
        return {"message": err, "status": "error"}, 400
    auth.audit("result_saved", f"{meta['id']} {meta['name']}")
    return {"message": "Result saved", "run": meta}


@app.route("/api/runs/<rid>", methods=["PATCH", "DELETE"])
def api_run_change(rid):
    meta = saved_runs.get_run(rid)
    if not _can_see_run(meta):
        return {"message": "Saved result not found."}, 404
    if request.method == "DELETE":
        saved_runs.delete_run(rid)
        auth.audit("result_deleted", f"{rid} {meta['name']}")
        return {"message": "Deleted"}
    body = request.get_json(silent=True) or {}
    m = saved_runs.rename_run(rid, body.get("name"))
    auth.audit("result_renamed", f"{rid} -> {m['name']}")
    return {"message": "Renamed", "run": m}


@app.route("/api/runs/<rid>/view/<key>")
def api_run_view(rid, key):
    if not _can_see_run(saved_runs.get_run(rid)):
        return {"error": "Not found"}, 404
    data = saved_runs.preview(rid, key)
    return jsonify(data) if data else ({"error": "File not found"}, 404)


@app.route("/saved/<rid>/download/<key>")
def saved_download(rid, key):
    if not _can_see_run(saved_runs.get_run(rid)):
        abort(404)
    p = saved_runs.file_path(rid, key)
    if not p:
        abort(404)
    auth.audit("download_saved", f"{rid}/{key}")
    return send_file(p, as_attachment=True)


# ========== SUPER ADMIN: DEBUG / INTERFACE / SETTINGS / USERS ==========
@app.route("/admin/debug")
@auth.admin_required
def page_debug():
    return render_template("admin_debug.html", page="debug")


@app.route("/admin/interface")
@auth.admin_required
def page_interface():
    return render_template("admin_interface.html", page="interface")


@app.route("/admin/settings")
@auth.admin_required
def page_settings():
    return render_template("admin_settings.html", page="settings")


@app.route("/admin/users")
@auth.admin_required
def page_users():
    return render_template("admin_users.html", page="users")


@app.route("/api/admin/debug")
@auth.admin_required
def api_debug():
    files = []
    for label, path in [("Packet capture", "data/traffic.pcapng"), ("Features", "data/features.csv"),
                        ("Sensitivity results", "data/results.csv"), ("Policy decisions", "data/policy.csv"),
                        ("Encrypted results", "data/encrypted_results.csv"),
                        ("Benchmark summary", "data/benchmark_summary.csv"), ("Timings", "data/timings.json")]:
        if os.path.exists(path):
            files.append({"name": label, "path": path, "bytes": os.path.getsize(path), "modified": os.path.getmtime(path)})
        else:
            files.append({"name": label, "path": path, "bytes": None, "modified": None})
    try:
        timings = json.load(open("data/timings.json")) if os.path.exists("data/timings.json") else {}
    except Exception:
        timings = {}
    return jsonify({
        "checks": diagnostics_data(),
        "pipeline": {"running": pipeline_active(), "run_by": last_run["user"], "mode": last_run["mode"],
                     "started": last_run["started"], "status": StatusManager.get_status(), "timings": timings.get("modules", {})},
        "comparison": {"running": bool(comparison.STATE.get("running")), "error": comparison.STATE.get("error"),
                       "message": comparison.STATE.get("message", "")},
        "files": files,
        "log": auth.audit_tail(150),
    })


@app.route("/api/admin/interface")
@auth.admin_required
def api_interface():
    from packet_capture import PacketCapture
    cap = PacketCapture()
    nics = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            ipv4 = [a.address for a in addrs if getattr(a.family, "name", str(a.family)) == "AF_INET"]
            st = stats.get(name)
            nics.append({"name": name, "ipv4": ipv4[0] if ipv4 else None, "up": bool(st and st.isup),
                         "speed": (st.speed if st and st.speed else None), "mtu": st.mtu if st else None,
                         "capture": name == cap.interface})
    except Exception:
        pass
    nics.sort(key=lambda n: (not n["capture"], not n["up"], n["name"]))
    return jsonify({
        "capture_interface": cap.interface, "target_packets": cap.target_packets,
        "min_packets": cap.min_acceptable_packets, "output_file": cap.output_file,
        "network": network_state, "pipeline_running": bool(service.current()),
        "tools": diagnostics_data(), "interfaces": nics,
    })


@app.route("/api/admin/network/prepare", methods=["POST"])
@auth.admin_required
def network_prepare():
    if service.current():
        return {"message": f"'{service.current()}' is running. Wait for it to finish.", "status": "busy"}, 409
    if not check_sudo_access():
        return {"message": "Passwordless sudo is not available. Allow it only for the commands this app needs.", "status": "error"}, 403
    if not check_mininet_installed():
        return {"message": "Mininet is not installed.", "status": "error"}, 400
    try:
        subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=20)
        time.sleep(1)
    except Exception as e:
        network_state.update(ready=False, message=f"Cleanup failed: {e}", updated=time.time())
        return {"message": network_state["message"], "status": "error"}, 500
    network_state.update(ready=True, message="Stale switches and namespaces removed. Ready for a capture.", updated=time.time())
    auth.audit("network_prepare")
    return {"message": network_state["message"], "status": "ready"}


@app.route("/api/admin/network/stop", methods=["POST"])
@auth.admin_required
def network_stop():
    try:
        subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=15)
    except Exception:
        pass
    network_state.update(ready=False, message="Test network stopped", updated=time.time())
    auth.audit("network_stop")
    return {"message": network_state["message"], "status": "stopped"}


@app.route("/api/admin/settings", methods=["GET", "POST"])
@auth.admin_required
def api_settings():
    if request.method == "POST":
        s, err = auth.save_settings(request.get_json(silent=True) or {})
        if err:
            return {"message": err, "status": "error"}, 400
        auth.audit("settings_changed", json.dumps(s))
        return {"message": "Settings saved", "settings": s}
    from policy_engine import get_limits
    C, M, _ = get_limits()
    return jsonify({"settings": auth.get_settings(), "cpu_limit": C, "mem_limit": M})


@app.route("/api/admin/users", methods=["GET", "POST"])
@auth.admin_required
def api_users():
    if request.method == "POST":
        b = request.get_json(silent=True) or {}
        u, err = auth.create_user((b.get("username") or "").strip(), b.get("password"), b.get("role", "user"),
                                  b.get("display_name", ""))
        if err:
            return {"message": err, "status": "error"}, 400
        auth.audit("user_created", f"{u['username']} ({u['role']})")
        return {"message": "User created", "user": u}
    return jsonify({"rows": auth.list_users(), "me": g.user["username"]})


@app.route("/api/admin/users/<username>", methods=["PATCH", "DELETE"])
@auth.admin_required
def api_user_change(username):
    if request.method == "DELETE":
        err = auth.delete_user(username, g.user["username"])
        if err:
            return {"message": err, "status": "error"}, 400
        auth.audit("user_deleted", username)
        return {"message": "User deleted"}
    b = request.get_json(silent=True) or {}
    changes = {k: b[k] for k in ("role", "active", "password", "display_name") if k in b}
    u, err = auth.update_user(username, changes, g.user["username"])
    if err:
        return {"message": err, "status": "error"}, 400
    auth.audit("user_changed", f"{username}: {', '.join(k if k != 'password' else 'password reset' for k in changes)}")
    return {"message": "User updated", "user": u}


# ========== ERRORS ==========
@app.errorhandler(403)
def forbidden(e):
    if auth.wants_json():
        return {"error": "Super admin access required."}, 403
    return render_template("error.html", page="error", code=403, title="Access restricted",
                           text="This page is available to super admins only."), 403


@app.errorhandler(404)
def not_found(e):
    if auth.wants_json():
        return {"error": "Not found"}, 404
    return render_template("error.html", page="error", code=404, title="Page not found",
                           text="The page you asked for does not exist."), 404


@app.errorhandler(500)
def server_error(e):
    return {"error": "Server error"}, 500


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    print("\n" + "=" * 50)
    print("        APQCRYPT DASHBOARD STARTING")
    print("=" * 50)
    print(f"Data directory : {os.path.abspath('data')}")
    print(f"Sudo access    : {check_sudo_access()}")
    print(f"Mininet        : {check_mininet_installed()}")
    print(f"tshark         : {check_tshark_installed()}")
    print(f"ML-KEM (oqs)   : {check_oqs()}")
    try:
        print(f"API key file   : data/api_key.txt (key created: {bool(get_key())})")
    except Exception:
        pass
    if not auth.has_users():
        print("\nFirst run: open the address below to create the super admin account.")
    print("=" * 50 + "\n")
    app.run(host=os.environ.get("APQ_HOST", "127.0.0.1"), port=5000, debug=False, use_reloader=False, threaded=True)
