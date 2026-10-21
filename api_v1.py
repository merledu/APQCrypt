"""
REST API v1 (the "wrapper interface" other systems can call).

  GET  /api/v1/health            no key   service status
  GET  /api/v1/openapi.json      no key   description of every endpoint (the Interfaces page uses it)
  POST /api/v1/decide            key      protection decision for ONE conversation
  POST /api/v1/analyze           key      upload a capture, analyse it as a background job
  GET  /api/v1/jobs/<id>         key      job status and summary
  GET  /api/v1/jobs/<id>/decisions key    one decision per conversation (JSON, or ?format=csv)
  GET  /api/v1/config            key      the settings in use

Key: send the header  X-API-Key: <key>.  The key is created on first start in data/api_key.txt.
"""
import hmac
import os
import re
import secrets
import threading
from functools import wraps

from flask import Blueprint, request, jsonify, send_file

import config as cfgmod
import interfaces
import service

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
KEY_FILE = "data/api_key.txt"
MAX_UPLOAD = 20 * 1024 * 1024
PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
_key_lock = threading.Lock()


def get_key():
    with _key_lock:
        try:
            with open(KEY_FILE) as f:
                k = f.read().strip()
                if k:
                    return k
        except OSError:
            pass
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
        k = secrets.token_urlsafe(24)
        with open(KEY_FILE, "w") as f:
            f.write(k)
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
        return k


def err(message, status=400, details=None):
    body = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


def keyed(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        given = request.headers.get("X-API-Key", "")
        if not given or not hmac.compare_digest(given, get_key()):
            return err("missing or wrong API key (send the header X-API-Key)", 401)
        return fn(*a, **kw)
    return wrapper


# ------------------------------------------------------------------ documentation
EXAMPLES = {
    "decide_bank": {"protocol": "HTTPS", "dest_port": 443, "source_port": 51000, "resource_status": "AVAILABLE"},
    "decide_ntp": {"protocol": "NTP", "dest_port": 123, "source_port": 50003, "resource_status": "CONSTRAINED"},
}


def spec():
    return {
        "openapi": "3.0.3",
        "info": {"title": "APQCrypt API", "version": "1.0", "description": "Ask APQCrypt which protection a conversation needs, or analyse a capture file."},
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/health": {"get": {"summary": "Service status and external connections", "auth": False}},
            "/decide": {"post": {"summary": "Decide the protection for ONE conversation", "auth": True,
                                 "body": {"protocol": "TCP|UDP|HTTP|HTTPS|SSH|DNS|NTP|ICMP|ARP|OTHER", "dest_port": "0-65535",
                                          "source_port": "optional", "payload_hex": "optional, first bytes of the data as hex (max 2048 chars)",
                                          "tcp_flags": "optional, e.g. PA", "packet_length": "optional",
                                          "resource_status": "optional: AVAILABLE or CONSTRAINED (default: measure now)",
                                          "mode": "optional: adaptive | static_aes | static_pqc"},
                                 "example": EXAMPLES["decide_bank"]}},
            "/analyze": {"post": {"summary": "Upload a .pcap/.pcapng (multipart field 'pcap') and analyse it as a job", "auth": True,
                                  "form": {"pcap": "file (max 20 MB)", "mode": "adaptive|static_aes|static_pqc", "force_resource": "AVAILABLE|CONSTRAINED (optional)",
                                           "encrypt": "true|false (default false: decisions only)"}}},
            "/jobs/{id}": {"get": {"summary": "Job status and summary", "auth": True}},
            "/jobs/{id}/decisions": {"get": {"summary": "One decision per conversation (add ?format=csv for CSV)", "auth": True}},
            "/config": {"get": {"summary": "The settings in use", "auth": True}},
        },
    }


@bp.route("/health")
def health():
    rows = interfaces.health()
    return jsonify({"status": "ok", "service": "APQCrypt", "api_version": "1.0", "busy": service.current(),
                    "connections": [{"kind": r["kind"], "name": r["name"], "active": r["active"], "available": r["available"]} for r in rows]})


@bp.route("/openapi.json")
def openapi():
    return jsonify(spec())


@bp.route("/key")
def local_key():
    """Used only by the Interfaces page on this computer, so the explorer can send requests."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return err("the key can only be shown on the computer running APQCrypt", 403)
    return jsonify({"key": get_key()})


# ------------------------------------------------------------------ decide (one conversation)
def _validate_decide(b):
    errors, row = [], {}
    if not isinstance(b, dict):
        return None, ["body must be a JSON object"]
    proto = str(b.get("protocol", "TCP")).upper()
    if proto not in cfgmod.PROTOCOLS:
        errors.append(f"protocol: choose one of {cfgmod.PROTOCOLS}")
    for key, lo, hi, default in (("dest_port", 0, 65535, None), ("source_port", 0, 65535, 0), ("packet_length", 0, 65535, 0)):
        v = b.get(key, default)
        if v is None:
            errors.append(f"{key}: required")
            continue
        try:
            iv = int(v)
            if isinstance(v, bool) or not (lo <= iv <= hi):
                raise ValueError
            row[key] = iv
        except (TypeError, ValueError):
            errors.append(f"{key}: must be a whole number {lo}-{hi}")
    hexs = str(b.get("payload_hex", "") or "")
    if hexs and (len(hexs) > 2048 or len(hexs) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", hexs)):
        errors.append("payload_hex: even-length hex text, at most 2048 characters")
    flags = str(b.get("tcp_flags", "") or "")
    if not re.fullmatch(r"[FSRPAUEC]{0,8}", flags):
        errors.append("tcp_flags: letters from FSRPAUEC only")
    res = b.get("resource_status")
    if res not in (None, "AVAILABLE", "CONSTRAINED"):
        errors.append("resource_status: AVAILABLE or CONSTRAINED")
    mode = b.get("mode", "adaptive")
    if mode not in ("adaptive", "static_aes", "static_pqc"):
        errors.append("mode: adaptive, static_aes or static_pqc")
    if errors:
        return None, errors
    row.update(protocol=proto, payload_hex=hexs.lower(), tcp_flags=flags, resource_status=res, mode=mode)
    return row, []


@bp.route("/decide", methods=["POST"])
@keyed
def decide():
    row, errors = _validate_decide(request.get_json(silent=True))
    if errors:
        return err("invalid request", 400, errors)
    import pandas as pd
    import sensitivity_engine as se
    import policy_engine as pe
    df = pd.DataFrame([{
        "Pkt_Index": 0, "Flow_ID": "api", "Source_IP": "0.0.0.0", "Destination_IP": "0.0.0.0",
        "Source_Port": row["source_port"], "Dest_Port": row["dest_port"], "Protocol": row["protocol"],
        "Packet_Length": row["packet_length"], "TTL": 64, "TCP_Flags": row["tcp_flags"], "Window": 0,
        "Payload_Len": len(row["payload_hex"]) // 2, "First_Bytes_Hex": row["payload_hex"]}])
    try:
        model = se.get_cached_model(se.MODEL_PATH)
    except Exception:
        model = None                                     # rules only; reported in the answer
    out, stats = se.score_dataframe(df, model)
    r = out.iloc[0]
    resource = row["resource_status"] or pe.get_resource_status()["status"]
    d = pe.decide(str(r["Sensitivity"]), resource, row["mode"])
    return jsonify({
        "sensitivity": str(r["Sensitivity"]), "score": float(r["Final_Score"]),
        "confidentiality_score": float(r["Confidentiality_Score"]), "confidentiality_signal": str(r["Confidentiality_Signal"]),
        "peek": str(r["DPI_Signal"]), "risk_tier": str(r["Risk_Tier"]), "risk_confidence": float(r["Risk_Confidence"]),
        "risk_model_used": stats["model_used"], "reason": str(r["Reason"]),
        "resource_status": resource, "mode": row["mode"],
        "decision": {"algorithm": d["algorithm"], "key_exchange": d["kex"], "cipher": d["symmetric_cipher"],
                     "policy": d["policy"], "quantum_safe": d["kex"].startswith("HYBRID")},
    })


# ------------------------------------------------------------------ analyze (upload a capture)
@bp.route("/analyze", methods=["POST"])
@keyed
def analyze():
    f = request.files.get("pcap")
    if f is None:
        return err("upload a capture in the multipart field 'pcap'")
    mode = request.form.get("mode", "adaptive")
    force = request.form.get("force_resource") or None
    encrypt = request.form.get("encrypt", "false").lower() == "true"
    problems = []
    if mode not in ("adaptive", "static_aes", "static_pqc"):
        problems.append("mode: adaptive, static_aes or static_pqc")
    if force not in (None, "AVAILABLE", "CONSTRAINED"):
        problems.append("force_resource: AVAILABLE or CONSTRAINED")
    if problems:
        return err("invalid request", 400, problems)
    data = f.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        return err("file too large (max 20 MB)", 413)
    if data[:4] not in PCAP_MAGIC:
        return err("this does not look like a .pcap or .pcapng file", 400)
    if not service.try_start("api job"):
        return err(f"busy: '{service.current()}' is running. Try again when it finishes.", 409)
    try:
        job = service.new_job(mode, force, encrypt, os.path.basename(f.filename or "upload")[:80])
        path = os.path.join("data", "uploads", job["id"] + ".pcapng")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(data)
    except Exception as e:
        service.finish()
        return err(f"could not store the upload: {e}", 500)
    threading.Thread(target=service.run_job, args=(job["id"], path), daemon=True).start()
    return jsonify({"job_id": job["id"], "status": "queued", "status_url": f"/api/v1/jobs/{job['id']}"}), 202


@bp.route("/jobs/<job_id>")
@keyed
def job_status(job_id):
    if not re.fullmatch(r"[0-9a-f]{12}", job_id):
        return err("unknown job", 404)
    job = service.get_job(job_id)
    return jsonify(job) if job else err("unknown job", 404)


@bp.route("/jobs/<job_id>/decisions")
@keyed
def job_decisions(job_id):
    if not re.fullmatch(r"[0-9a-f]{12}", job_id):
        return err("unknown job", 404)
    job = service.get_job(job_id)
    if not job:
        return err("unknown job", 404)
    if job["status"] != "done":
        return err(f"job is {job['status']}", 409)
    path = os.path.join(service.JOB_DIR, job_id, "policy.csv")
    if request.args.get("format") == "csv":
        return send_file(path, mimetype="text/csv", as_attachment=True, download_name=f"decisions_{job_id}.csv")
    return jsonify({"job_id": job_id, "decisions": service.decisions_from_policy(path)})


@bp.route("/config")
@keyed
def config_view():
    return jsonify(cfgmod.get_all())
