from flask import Flask, render_template, jsonify, send_file, request
import subprocess
import os
import io
import math
import time
import zipfile
import pandas as pd
from status_manager import StatusManager
import threading
import json
import config as cfgmod
import debuglog
import interfaces
import service
import comparison
from api_v1 import bp as api_v1_bp, get_key

app = Flask(__name__)

app.register_blueprint(api_v1_bp)          # REST API: /api/v1/...

# ----- run state (only ONE of: pipeline run, comparison, API job at a time: see service.py) -----
pipeline_thread = None
STAGES = ["capture", "features", "sensitivity", "policy", "encryption"]
STAGE_INFO = [("capture", "Packet capture", "data/traffic.pcapng"), ("features", "Feature extraction", "data/features.csv"),
              ("sensitivity", "Sensitivity scoring", "data/results.csv"), ("policy", "Policy decision", "data/policy.csv"),
              ("encryption", "Encryption", "data/encrypted_results.csv")]

os.makedirs("data", exist_ok=True)

# Tabs shown on every page: (key, label, url)
NAV = [
    ("capture", "1 · Capture & Features", "/"),
    ("sensitivity", "2 · Sensitivity", "/sensitivity"),
    ("resources", "3 · System condition", "/resources"),
    ("encryption", "4 · Encryption", "/encryption"),
    ("compare", "5 · Compare", "/compare"),
    ("debug", "6 · Debug", "/debug"),
    ("interfaces", "7 · Interfaces", "/interfaces"),
    ("settings", "8 · Settings", "/settings"),
]


@app.context_processor
def inject_nav():
    return {"nav": NAV}


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


@app.route("/diagnostics")
def diagnostics():
    return jsonify({
        "sudo_access": check_sudo_access(),
        "mininet_installed": check_mininet_installed(),
        "tshark_installed": check_tshark_installed(),
        "liboqs_mlkem": check_oqs(),
        "data_dir_exists": os.path.isdir("data"),
        "message": "All checks required for pipeline to work"
    })


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


@app.route("/debug")
def page_debug():
    return render_template("debug.html", page="debug")


@app.route("/interfaces")
def page_interfaces():
    return render_template("interfaces.html", page="interfaces")


@app.route("/settings")
def page_settings():
    return render_template("settings.html", page="settings")


# ========== TEST NETWORK (honest label: no external SDN controller is running) ==========
@app.route("/start-osken", methods=["POST"])
def start_osken():
    try:
        if not check_sudo_access():
            return {"message": "Error: No sudo access. Allow passwordless sudo only for the commands this app needs.", "status": "error"}, 403
        if not check_mininet_installed():
            return {"message": "Error: Mininet not installed", "status": "error"}, 400
        try:
            subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=20)
            time.sleep(1)
        except Exception as e:
            print(f"Cleanup warning: {e}")
        StatusManager.update_status("OSKen", "Open vSwitch test network ready (standalone switch, no external SDN controller)", 0)
        return {"message": "Test network ready", "status": "started"}
    except Exception as e:
        error_msg = f"Error preparing test network: {str(e)}"
        StatusManager.update_status("Error", error_msg)
        return {"message": error_msg, "status": "error"}, 500


@app.route("/stop-osken", methods=["POST"])
def stop_osken():
    try:
        try:
            subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=15)
        except Exception:
            pass
        StatusManager.update_status("OSKen", "Test network stopped", 0)
        return {"message": "Test network stopped"}
    except Exception as e:
        return {"message": f"Error: {str(e)}", "status": "error"}, 500


# ========== START PIPELINE ==========
@app.route("/start-pipeline", methods=["POST"])
def start_pipeline():
    global pipeline_thread

    mode = request.args.get("mode", "adaptive")
    if mode not in ("adaptive", "static_aes", "static_pqc"):
        mode = "adaptive"
    force = request.args.get("force")
    if force not in ("AVAILABLE", "CONSTRAINED"):
        force = None
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
        return {"message": "No previous capture to reuse. Untick 'Reuse last capture'.", "status": "error"}, 400
    if start_idx > 0:
        needed = [info[2] for info in STAGE_INFO[:start_idx]]
        missing = [p for p in needed if not os.path.exists(p)]
        if missing:
            return {"message": f"Cannot start from '{start_from}': missing {', '.join(missing)}. Run the full pipeline first.", "status": "error"}, 400
    needs_capture = start_idx == 0 and not replay and interfaces.active_name("packet_source") == "mininet"
    if needs_capture:
        if not check_sudo_access():
            return {"message": "Error: No sudo access (see Interfaces page for details)", "status": "error"}, 403
        if not check_mininet_installed():
            return {"message": "Error: Mininet not installed", "status": "error"}, 400
        if not check_tshark_installed():
            return {"message": "Error: tshark not installed", "status": "error"}, 400

    if not service.try_start("pipeline"):
        return {"message": f"'{service.current()}' is already running. Wait for it to finish.", "status": "busy"}, 409

    # Reset the status file NOW so the page never reads the previous run's "Finished".
    StatusManager.update_status("Starting", f"Pipeline starting ({mode})...", 0)

    def run_pipeline():
        from main_controller import PipelineController
        try:
            PipelineController().run(mode=mode, replay_pcap=replay, force_resource=force,
                                     stop_after=stop_after, start_from=start_from)
        except Exception as e:
            import traceback
            traceback.print_exc()
            StatusManager.update_status("Error", f"Pipeline failed: {str(e)}")
        finally:
            service.finish()

    pipeline_thread = threading.Thread(target=run_pipeline, daemon=True)
    pipeline_thread.start()
    return {"message": "Pipeline started in background", "status": "running"}


# ========== STATUS ==========
@app.route("/status")
def status():
    try:
        return jsonify(StatusManager.get_status())
    except Exception as e:
        print(f"Status error: {e}")
        return jsonify({"stage": "Idle", "message": "No status available", "progress": 0})


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
        rows = [{"sensitivity": s, "resources": r, "algorithm": d["algorithm"], "kex": d["kex"],
                 "cipher": d["symmetric_cipher"], "policy": d["policy"],
                 "pqc_handshake": d["kex"].startswith("HYBRID")} for (s, r), d in get_decision_matrix().items()]
        return jsonify({"rows": rows, "cpu_limit": C, "mem_limit": M})
    except Exception as e:
        return {"error": str(e)}, 500


# ========== COMPARISON (normal vs everything-quantum-safe vs adaptive) ==========
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
    force = b.get("force") if b.get("force") in ("AVAILABLE", "CONSTRAINED") else None
    problem = comparison.preflight(modes)
    if problem:
        return {"message": problem}, 400
    if not service.try_start("comparison"):
        return {"message": f"'{service.current()}' is already running. Wait for it to finish."}, 409
    comparison.start(modes, runs, force, bool(b.get("interleave", True)))
    return {"ok": True, "message": "Measuring started", "total_runs": len(modes) * (runs + 1)}


@app.route("/api/comparison/micro", methods=["POST"])
def api_comparison_micro():
    if not service.try_start("comparison"):
        return {"message": f"'{service.current()}' is already running. Wait for it to finish."}, 409
    comparison.start_micro()
    return {"ok": True}


@app.route("/api/comparison/cancel", methods=["POST"])
def api_comparison_cancel():
    comparison.cancel()
    return {"ok": True}


@app.route("/api/comparison/clear", methods=["POST"])
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
    return {"ok": True, "removed": n}


@app.route("/api/comparison/export.csv")
def api_comparison_export():
    return send_file(io.BytesIO(comparison.evidence_csv().encode("utf-8")), mimetype="text/csv", as_attachment=True,
                     download_name="apqcrypt_comparison_evidence.csv")


# ========== CONFIGURATION INTERFACE (Settings page) ==========
@app.route("/api/config", methods=["GET", "PUT"])
def api_config():
    if request.method == "PUT":
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("config"), dict):
            return {"errors": ["send JSON like {\"config\": {...}}"]}, 400
        try:
            saved = cfgmod.save(body["config"], merge=True)
        except cfgmod.ConfigError as e:
            return {"errors": e.errors}, 400
        return {"ok": True, "config": saved}
    return jsonify({"config": cfgmod.get_all(), "defaults": cfgmod.DEFAULTS, "presets": cfgmod.preset_list(),
                    "choices": {"kex": cfgmod.KEX_CHOICES, "cipher": cfgmod.CIPHER_CHOICES, "protocols": cfgmod.PROTOCOLS,
                                "packet_sources": cfgmod.PACKET_SOURCES, "crypto_providers": cfgmod.CRYPTO_PROVIDERS},
                    "saved": os.path.exists(cfgmod.CONFIG_FILE)})


@app.route("/api/config/reset", methods=["POST"])
def api_config_reset():
    return {"ok": True, "config": cfgmod.reset()}


@app.route("/api/config/preset/<name>", methods=["POST"])
def api_config_preset(name):
    try:
        return {"ok": True, "config": cfgmod.apply_preset(name)}
    except cfgmod.ConfigError as e:
        return {"errors": e.errors}, 400


@app.route("/api/config/export")
def api_config_export():
    data = json.dumps(cfgmod.get_all(), indent=2).encode()
    return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True, download_name="apqcrypt_config.json")


# ========== WRAPPER INTERFACE (external connections) ==========
@app.route("/api/interfaces")
def api_interfaces():
    return jsonify({"rows": interfaces.health(), "base_url": request.host_url.rstrip("/") + "/api/v1"})


@app.route("/api/interfaces/test", methods=["POST"])
def api_interfaces_test():
    b = request.get_json(silent=True) or {}
    res = interfaces.test(b.get("kind"), b.get("name"))
    return (jsonify(res), 200) if res else ({"error": "unknown connection"}, 404)


@app.route("/api/interfaces/select", methods=["POST"])
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
    return {"ok": True, "active": interfaces.active_name(kind)}


# ========== DEBUGGING INTERFACE ==========
def _csv_rows(path):
    try:
        with open(path, "rb") as f:
            return max(sum(1 for _ in f) - 1, 0)
    except OSError:
        return None


@app.route("/api/debug/events")
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
    steps.append({"step": 4, "title": "AI behaviour risk (Random Forest)", "summary": f"AI said {tiers} (average confidence {round(float(conf.mean()), 2)})",
                  "details": {"risk_tiers": tiers, "average_confidence": round(float(conf.mean()), 3),
                              "unsure_packets": int((conf < S["uncertain_confidence"]).sum()), "unsure_below": S["uncertain_confidence"],
                              "unsure_rule": "raise to MEDIUM" if S["raise_when_uncertain"] else "ignore"}})
    steps.append({"step": 5, "title": "Combine (MAX) and decide the level",
                  "summary": f"final score {float(rows['Final_Score'].max())} → {_first(rows, 'Sensitivity')}",
                  "details": {"best_packet_score": float(rows["Packet_Score"].max()), "final_score": float(rows["Final_Score"].max()),
                              "sensitivity": _first(rows, "Sensitivity"), "high_threshold": S["high_threshold"], "medium_threshold": S["medium_threshold"],
                              "first_n_packets_used": S["flow_first_n"], "reason": _first(rows, "Reason")}})
    if "Selected_Algorithm" in rows.columns:
        steps.append({"step": 6, "title": "Policy (decision table)", "summary": f"{_first(rows, 'Sensitivity')} + {_first(rows, 'Resource_Status')} → {_first(rows, 'Selected_Algorithm')}",
                      "details": {"mode": _first(rows, "Mode"), "computer_condition": _first(rows, "Resource_Status"),
                                  "cpu_percent": None if pd.isna(_first(rows, "CPU_Percent")) else _first(rows, "CPU_Percent"),
                                  "memory_percent": None if pd.isna(_first(rows, "Memory_Percent")) else _first(rows, "Memory_Percent"),
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
def api_debug_run_config():
    try:
        with open("data/run_config.json") as f:
            return jsonify(json.load(f))
    except (OSError, ValueError):
        return {"error": "no run yet"}, 404


@app.route("/api/debug/bundle")
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


@app.errorhandler(404)
def not_found(e):
    return {"error": "Not found"}, 404


@app.errorhandler(500)
def server_error(e):
    return {"error": "Server error"}, 500


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    print("\n" + "=" * 50)
    print("        APQCRYPT DASHBOARD STARTING")
    print("=" * 50)
    print(f"✓ Data directory: {os.path.abspath('data')}")
    print(f"✓ Sudo access: {check_sudo_access()}")
    print(f"✓ Mininet installed: {check_mininet_installed()}")
    print(f"✓ Tshark installed: {check_tshark_installed()}")
    print(f"✓ ML-KEM available: {check_oqs()}")
    print(f"✓ API key file: data/api_key.txt (key created: {bool(get_key())})")
    print("=" * 50 + "\n")
    app.run(host=os.environ.get("APQ_HOST", "127.0.0.1"), port=5000, debug=False, use_reloader=False, threaded=True)
