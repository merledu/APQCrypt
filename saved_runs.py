"""
Saved results: a snapshot of one pipeline run kept under data/saved/<id>/.

The pipeline always overwrites data/*.csv with the newest run. Saving copies those
files, plus a small summary, so a result can be reopened or downloaded later.
"""
import json
import os
import re
import secrets
import shutil
import time

import pandas as pd

SAVED_DIR = os.path.join("data", "saved")
ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")

# download key -> file name inside a snapshot
FILES = {
    "packets": "traffic.pcapng",
    "features": "features.csv",
    "results": "results.csv",
    "policy": "policy.csv",
    "encrypted": "encrypted_results.csv",
    "benchmark": "benchmark_summary.csv",
}
SOURCES = {
    "traffic.pcapng": "data/traffic.pcapng",
    "features.csv": "data/features.csv",
    "results.csv": "data/results.csv",
    "policy.csv": "data/policy.csv",
    "encrypted_results.csv": "data/encrypted_results.csv",
    "benchmark_summary.csv": "data/benchmark_summary.csv",
    "benchmark_summary.json": "data/benchmark_summary.json",
    "timings.json": "data/timings.json",
    "encryption_checks.json": "data/encryption_checks.json",
}


def has_results():
    return os.path.exists("data/results.csv") and os.path.exists("data/encrypted_results.csv")


def _summary():
    """Headline numbers of the current run, stored next to the files."""
    s = {}
    try:
        if os.path.exists("data/features.csv"):
            s["packets"] = int(len(pd.read_csv("data/features.csv", usecols=[0])))
        if os.path.exists("data/results.csv"):
            r = pd.read_csv("data/results.csv")
            if "Sensitivity" in r.columns:
                s["sensitivity"] = {k: int(v) for k, v in r["Sensitivity"].value_counts().items()}
        if os.path.exists("data/policy.csv"):
            p = pd.read_csv("data/policy.csv")
            if "Mode" in p.columns and len(p):
                s["mode"] = str(p["Mode"].iloc[0])
            if "Resource_Status" in p.columns and len(p):
                s["resource_status"] = str(p["Resource_Status"].iloc[0])
        if os.path.exists("data/timings.json"):
            with open("data/timings.json") as f:
                s["total_time"] = json.load(f).get("modules", {}).get("Total Execution")
    except Exception:
        pass
    return s


def save_current(name, owner):
    if not has_results():
        return None, "There is no finished run to save. Run the pipeline first."
    name = (name or "").strip()[:80] or time.strftime("Run %Y-%m-%d %H:%M")
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    folder = os.path.join(SAVED_DIR, rid)
    os.makedirs(folder, exist_ok=True)
    kept = []
    for fname, src in SOURCES.items():
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(folder, fname))
            kept.append(fname)
    meta = {"id": rid, "name": name, "owner": owner, "created": time.time(),
            "files": kept, "summary": _summary()}
    with open(os.path.join(folder, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return meta, None


def _meta(rid):
    if not ID_RE.match(rid or ""):
        return None
    try:
        with open(os.path.join(SAVED_DIR, rid, "meta.json"), encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return None


def list_runs(owner=None):
    """All runs (owner=None) or only one user's runs, newest first."""
    out = []
    if os.path.isdir(SAVED_DIR):
        for rid in os.listdir(SAVED_DIR):
            m = _meta(rid)
            if m and (owner is None or m.get("owner") == owner):
                out.append(m)
    return sorted(out, key=lambda m: m.get("created", 0), reverse=True)


def get_run(rid):
    return _meta(rid)


def file_path(rid, key):
    """Absolute path of one file inside a snapshot, or None. Only names from FILES are allowed."""
    fname = FILES.get(key)
    m = _meta(rid)
    if not fname or not m or fname not in m.get("files", []):
        return None
    p = os.path.abspath(os.path.join(SAVED_DIR, rid, fname))
    return p if os.path.exists(p) else None


def preview(rid, key, rows=50):
    p = file_path(rid, key)
    if not p or not p.endswith(".csv"):
        return None
    df = pd.read_csv(p)
    recs = df.head(rows).astype(object).where(df.head(rows).notna(), None).to_dict("records")
    return {"columns": list(df.columns), "data": recs, "total_rows": int(len(df))}


def rename_run(rid, name):
    m = _meta(rid)
    if not m:
        return None
    m["name"] = (name or "").strip()[:80] or m["name"]
    with open(os.path.join(SAVED_DIR, rid, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
    return m


def delete_run(rid):
    if not _meta(rid):
        return False
    shutil.rmtree(os.path.join(SAVED_DIR, rid), ignore_errors=True)
    return True
