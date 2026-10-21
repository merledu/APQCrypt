import os
import time
import pandas as pd

try:
    import psutil
except ImportError:
    psutil = None

from status_manager import StatusManager
import config as cfgmod
import debuglog

# =====================================================================
#  SETTINGS come from config.py (Settings page): CPU / memory limits, number of readings,
#  and the decision table (sensitivity x computer condition -> key exchange + lock).
#  Rules enforced by the settings check: 1) HIGH must be quantum-safe (unless "allow unsafe"),
#  2) only tamper-detecting locks (AES-GCM, ChaCha20-Poly1305).
# =====================================================================

# Baselines used by the comparison (same for every packet)
STATIC_MODES = {
    "static_aes": {"algorithm": "X25519 / AES-256-GCM", "policy": "Static AES-256 Policy",
                   "kex": "X25519", "symmetric_cipher": "AES-256-GCM"},
    "static_pqc": {"algorithm": "X25519+ML-KEM-1024 / AES-256-GCM", "policy": "Static All-PQC Policy",
                   "kex": "HYBRID_1024", "symmetric_cipher": "AES-256-GCM"},
}


def get_decision_matrix():
    return cfgmod.decision_matrix()


def get_limits():
    r = cfgmod.get("resources")
    return float(r["cpu_limit"]), float(r["memory_limit"]), int(r["samples"])


def get_resource_status(force=None):
    """
    One reading per run, averaged over a short period.
    force = "AVAILABLE" or "CONSTRAINED" simulates a free/busy computer (demos and tests).
    NOTE: this measures the whole machine, which includes our own pipeline.
    """
    if force in ("AVAILABLE", "CONSTRAINED"):
        return {"cpu_percent": None, "memory_percent": None, "status": force, "reason": "forced (demo/test)"}
    cpu_limit, mem_limit, samples = get_limits()
    if psutil is None:
        return {"cpu_percent": None, "memory_percent": None, "status": "CONSTRAINED", "reason": "psutil not available"}
    cpu = sum(psutil.cpu_percent(interval=0.2) for _ in range(samples)) / samples
    mem = psutil.virtual_memory().percent
    status = "CONSTRAINED" if (cpu >= cpu_limit or mem >= mem_limit) else "AVAILABLE"
    return {"cpu_percent": round(cpu, 1), "memory_percent": round(mem, 1), "status": status}


def decide(sensitivity, resource_status, mode="adaptive"):
    """The decision for ONE conversation (also used by the REST API)."""
    if mode in STATIC_MODES:
        return dict(STATIC_MODES[mode])
    matrix = get_decision_matrix()
    return dict(matrix.get((sensitivity, resource_status)) or matrix[("HIGH", resource_status)])   # fail safe: unknown -> HIGH


class PolicyEngine:
    def __init__(self, output_file="data/policy.csv"):
        self.output_file = output_file
        self.start_time = None

    def select_policies(self, results_file, mode="adaptive", force_resource=None):
        """
        mode = "adaptive"   -> APQCrypt decision table (from Settings)
               "static_aes" -> baseline: X25519 + AES-256-GCM for everything
               "static_pqc" -> baseline: hybrid ML-KEM-1024 + AES-256-GCM for everything
        """
        try:
            if not os.path.exists(results_file):
                StatusManager.update_status("Policy", f"Error: Results file not found: {results_file}")
                debuglog.log("policy", "results file not found", "error", file=results_file)
                return None
            if mode not in ("adaptive", "static_aes", "static_pqc"):
                StatusManager.update_status("Policy", f"Error: unknown mode {mode}")
                return None

            self.start_time = time.time()
            cpu_limit, mem_limit, samples = get_limits()
            debuglog.log("policy", "stage_start", input=results_file, mode=mode,
                         params={"cpu_limit": cpu_limit, "memory_limit": mem_limit, "samples": samples,
                                 "forced_resource": force_resource})
            StatusManager.update_status("Policy", "Reading system resource status...", 92)
            resource = get_resource_status(force_resource)
            r_status = resource["status"]
            debuglog.log("policy", f"computer condition = {r_status}", cpu=resource["cpu_percent"], memory=resource["memory_percent"],
                         note=resource.get("reason", "measured"))

            df = pd.read_csv(results_file)
            if len(df) == 0 or "Sensitivity" not in df.columns:
                StatusManager.update_status("Policy", "Error: results file empty or 'Sensitivity' column missing")
                return None

            StatusManager.update_status("Policy", f"Applying {mode} policy ({len(df)} rows, resources: {r_status})...", 95)

            if mode == "adaptive":
                matrix = get_decision_matrix()
                lookup = pd.DataFrame([{"Sensitivity": s, **d} for (s, r), d in matrix.items() if r == r_status])
                df = df.merge(lookup, on="Sensitivity", how="left")
                high = matrix[("HIGH", r_status)]
                for col in ("algorithm", "policy", "kex", "symmetric_cipher"):      # fail safe: unknown -> HIGH decision
                    df[col] = df[col].fillna(high[col])
            else:
                for col, val in STATIC_MODES[mode].items():
                    df[col] = val

            df["PQC_Handshake_Used"] = df["kex"].str.startswith("HYBRID")
            df["Resource_Status"] = r_status
            df["CPU_Percent"] = resource["cpu_percent"]
            df["Memory_Percent"] = resource["memory_percent"]
            df["Mode"] = mode
            df["Policy_Reason"] = df["Sensitivity"].astype(str) + " + " + r_status + " -> " + df["algorithm"]
            df = df.rename(columns={"algorithm": "Selected_Algorithm", "policy": "Selected_Policy",
                                    "kex": "Key_Exchange", "symmetric_cipher": "Symmetric_Cipher"})

            tmp = self.output_file + ".tmp"
            df.to_csv(tmp, index=False)
            os.replace(tmp, self.output_file)

            secs = time.time() - self.start_time
            StatusManager.record_module_timing("Policy Engine", secs)
            msg = (f"✓ Policy Decisions Complete ({mode}) | Resources: {r_status} "
                   f"(CPU {resource['cpu_percent']}%, Mem {resource['memory_percent']}%) | "
                   f"Policies: {df['Selected_Policy'].value_counts().to_dict()} | File: {self.output_file}")
            print(f"[DEBUG] {msg}")
            print(f"[DEBUG] Algorithm distribution: {df['Selected_Algorithm'].value_counts().to_dict()}")
            StatusManager.update_status("Policy", msg, 98)
            debuglog.log("policy", "stage_end", rows_in=int(len(df)), rows_out=int(len(df)), seconds=round(secs, 3),
                         output=self.output_file, resource=r_status,
                         result={k: int(v) for k, v in df["Selected_Algorithm"].value_counts().items()})
            return self.output_file

        except Exception as e:
            import traceback
            print(f"[DEBUG] Policy engine error:\n{traceback.format_exc()}")
            StatusManager.update_status("Policy", f"Error: {str(e)}")
            debuglog.log("policy", "policy error", "error", error=str(e)[:200])
            return None
