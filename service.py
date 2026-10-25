"""
Shared run control + the analysis service used by the REST API.

* try_start()/finish(): only ONE of {pipeline run, comparison, API job} runs at a time.
* muted(): silences the dashboard status/debug output while an API job or the comparison runs.
* run_job(): analyse an uploaded capture (features -> sensitivity -> policy [-> encryption]) into its own folder.
"""
import contextlib
import json
import os
import threading
import time
import uuid

import debuglog
from status_manager import StatusManager

_run_lock = threading.Lock()
_current = {"task": None, "since": None}
JOBS = {}
JOB_DIR = "data/jobs"


def try_start(task):
    if _run_lock.acquire(blocking=False):
        _current.update(task=task, since=time.time())
        return True
    return False


def finish():
    _current.update(task=None, since=None)
    try:
        _run_lock.release()
    except RuntimeError:
        pass


def current():
    return _current["task"]


@contextlib.contextmanager
def muted():
    saved = (StatusManager.__dict__["update_status"], StatusManager.__dict__["record_module_timing"])
    StatusManager.update_status = staticmethod(lambda *a, **k: None)
    StatusManager.record_module_timing = staticmethod(lambda *a, **k: None)
    try:
        with debuglog.suspended():
            yield
    finally:
        StatusManager.update_status, StatusManager.record_module_timing = saved


def _save_job(job):
    try:
        os.makedirs(os.path.join(JOB_DIR, job["id"]), exist_ok=True)
        with open(os.path.join(JOB_DIR, job["id"], "job.json"), "w") as f:
            json.dump(job, f, indent=2, default=str)
    except OSError:
        pass


def get_job(job_id):
    if job_id in JOBS:
        return JOBS[job_id]
    try:
        with open(os.path.join(JOB_DIR, job_id, "job.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def new_job(mode, force, encrypt, filename):
    job = {"id": uuid.uuid4().hex[:12], "status": "queued", "mode": mode, "force_resource": force,
           "encrypt": encrypt, "filename": filename, "created": time.time(), "summary": None, "error": None}
    JOBS[job["id"]] = job
    _save_job(job)
    return job


def decisions_from_policy(path):
    import pandas as pd
    df = pd.read_csv(path)
    rows = []
    key = "Flow_ID" if "Flow_ID" in df.columns else None
    groups = df.groupby(key, sort=False) if key else [("all", df)]
    for fid, d in groups:
        first = d.iloc[0]
        peek = d["DPI_Signal"].dropna().astype(str) if "DPI_Signal" in d.columns else []
        rows.append({
            "flow": str(fid), "protocol": str(first.get("Protocol", "")), "dest_port": int(first.get("Dest_Port", 0) or 0),
            "packets": int(len(d)), "sensitivity": str(first.get("Sensitivity", "")),
            "score": float(first.get("Final_Score", 0) or 0), "peek": peek.iloc[0] if len(peek) else "",
            "key_exchange": str(first.get("Key_Exchange", "")), "cipher": str(first.get("Symmetric_Cipher", "")),
            "algorithm": str(first.get("Selected_Algorithm", "")), "reason": str(first.get("Reason", "")),
        })
    return rows


def run_job(job_id, pcap_path):
    job = JOBS[job_id]
    out = os.path.join(JOB_DIR, job_id)
    try:
        with muted():
            from feature_extraction import FeatureExtractor
            from sensitivity_engine import SensitivityEngine
            from policy_engine import PolicyEngine
            job.update(status="running"); _save_job(job)
            if job["mode"] == "adaptive" and not job["force_resource"]:
                from policy_engine import prefetch_resource_status
                prefetch_resource_status()              # the CPU reading waits in the background
            fe = FeatureExtractor(); fe.output_file = os.path.join(out, "features.csv")
            f = fe.extract_features(pcap_path)
            if not f:
                raise RuntimeError("feature extraction failed (is it a valid capture?)")
            se = SensitivityEngine(); se.output_file = os.path.join(out, "results.csv")
            r = se.classify_sensitivity(f)
            if not r:
                raise RuntimeError("sensitivity analysis failed")
            p = PolicyEngine(output_file=os.path.join(out, "policy.csv")).select_policies(
                r, mode=job["mode"], force_resource=job["force_resource"])
            if not p:
                raise RuntimeError("policy step failed")
            enc_note = None
            if job["encrypt"]:
                from encryption_engine import EncryptionEngine
                ee = EncryptionEngine(output_file=os.path.join(out, "encrypted_results.csv"))
                if not ee.encrypt_traffic(p, pcap_path):
                    enc_note = "encryption step failed (is liboqs installed?). Decisions are still valid."
            import pandas as pd
            pol = pd.read_csv(p)
            decisions = decisions_from_policy(p)
            job["summary"] = {
                "packets": int(len(pol)), "conversations": len(decisions),
                "sensitivity": {k: int(v) for k, v in pol["Sensitivity"].value_counts().items()},
                "key_exchanges": {k: int(v) for k, v in pol["Key_Exchange"].value_counts().items()},
                "algorithms": {k: int(v) for k, v in pol["Selected_Algorithm"].value_counts().items()},
                "encryption_note": enc_note,
            }
            job["status"] = "done"
    except Exception as e:
        job.update(status="failed", error=str(e)[:300])
    finally:
        job["finished"] = time.time()
        _save_job(job)
        finish()
