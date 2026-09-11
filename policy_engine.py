import os
import time
import pandas as pd

try:
    import psutil
except ImportError:
    psutil = None

from status_manager import StatusManager


# ── Resource Status thresholds ──────────────────────────────────────
# NOTE: These are design assumptions, not values measured from the
# RISC-V benchmark report (that report covers algorithm latency only,
# not device resource-monitoring thresholds -- the RISC-V board is
# not currently operational, so no real telemetry exists to calibrate
# these against). A simple 2-state model (Available / Constrained)
# was chosen deliberately for clarity and defensibility: it needs
# fewer assumed numbers than a 3+ state model, and CPU is used as the
# primary signal since it's the more volatile of the two under load.
CPU_CONSTRAINED_THRESHOLD = 50.0     # % CPU usage
MEMORY_CONSTRAINED_THRESHOLD = 70.0  # % memory used


# ── Decision Matrix ──────────────────────────────────────────────────
# Sensitivity (from sensitivity_engine.py's classification) x
# Resource Status (from live psutil reading) -> selected algorithm.
#
# Grounded in the RISC-V PQC benchmark (benchmark_analysis.docx):
#   - ML-KEM is the only PQC primitive fast enough for real-time use
#     on the target hardware (sub-millisecond keygen/encaps/decaps).
#   - Falcon and BIKE are excluded entirely: Falcon keygen >100ms,
#     BIKE decapsulation 126ms-1s -- the report's own conclusion
#     rules them out for interactive/real-time use.
#   - High-sensitivity traffic uses a hybrid scheme: ML-KEM performs
#     the quantum-safe key exchange, AES-256-GCM encrypts the actual
#     payload (ML-KEM itself is a KEM, not a bulk cipher).
#   - Under CPU/memory pressure, High-sensitivity traffic keeps its
#     strong AES-256 payload encryption but drops the extra PQC
#     handshake step -- a deliberate, documented trade-off rather
#     than a silent downgrade.
DECISION_MATRIX = {
    ("HIGH", "AVAILABLE"):   {"algorithm": "ML-KEM-1024 + AES-256-GCM", "policy": "High Security Policy",     "pqc_handshake": True,  "symmetric_cipher": "AES-256-GCM"},
    ("HIGH", "CONSTRAINED"): {"algorithm": "AES-256-GCM",                "policy": "High Security Policy",     "pqc_handshake": False, "symmetric_cipher": "AES-256-GCM"},
    ("MEDIUM", "AVAILABLE"):   {"algorithm": "AES-256-CBC", "policy": "Standard Security Policy", "pqc_handshake": False, "symmetric_cipher": "AES-256-CBC"},
    ("MEDIUM", "CONSTRAINED"): {"algorithm": "ChaCha20",     "policy": "Standard Security Policy", "pqc_handshake": False, "symmetric_cipher": "ChaCha20"},
    ("LOW", "AVAILABLE"):   {"algorithm": "AES-128-CBC", "policy": "Default Security Policy", "pqc_handshake": False, "symmetric_cipher": "AES-128-CBC"},
    ("LOW", "CONSTRAINED"): {"algorithm": "ChaCha20",     "policy": "Default Security Policy", "pqc_handshake": False, "symmetric_cipher": "ChaCha20"},
}


def get_resource_status():
    """
    Take ONE live reading of system resource state.

    Deliberately called once per pipeline run (not once per packet/row):
    resource load doesn't meaningfully change packet-to-packet within a
    single run, so per-row psutil calls would just be wasted overhead --
    same batching principle already applied in sensitivity_engine.py.
    """
    if psutil is None:
        # psutil not installed -- fail safe to CONSTRAINED so the
        # system prefers cheaper algorithms rather than assuming
        # resources are free.
        return {"cpu_percent": None, "memory_percent": None, "status": "CONSTRAINED", "reason": "psutil not available"}

    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent

    if cpu >= CPU_CONSTRAINED_THRESHOLD or mem >= MEMORY_CONSTRAINED_THRESHOLD:
        status = "CONSTRAINED"
    else:
        status = "AVAILABLE"

    return {"cpu_percent": round(cpu, 1), "memory_percent": round(mem, 1), "status": status}


class PolicyEngine:
    def __init__(self):
        self.output_file = "data/policy.csv"
        self.start_time = None

    def select_policies(self, results_file):
        """
        Reads sensitivity classification results, takes one resource
        reading, applies the Sensitivity x Resource decision matrix to
        every row via a single vectorized pandas operation (no
        per-row Python loop), and writes policy.csv.
        """
        try:
            if not os.path.exists(results_file):
                StatusManager.update_status("Policy", f"Error: Results file not found: {results_file}")
                return None

            self.start_time = time.time()
            StatusManager.update_status("Policy", "Reading system resource status...", 92)

            resource = get_resource_status()
            r_status = resource["status"]

            try:
                df = pd.read_csv(results_file)
            except Exception as e:
                StatusManager.update_status("Policy", f"Failed to read results file: {str(e)}")
                return None

            if len(df) == 0:
                StatusManager.update_status("Policy", "Error: Results file is empty")
                return None

            StatusManager.update_status(
                "Policy",
                f"Applying decision matrix ({len(df)} rows, resources: {r_status})...",
                95
            )

            if "Sensitivity" not in df.columns:
                StatusManager.update_status("Policy", "Error: 'Sensitivity' column missing from results file")
                return None

            # ---- Vectorized decision matrix lookup (no per-row loop) ----
            # Build one small lookup DataFrame keyed on Sensitivity, then
            # merge -- this scales to any packet count without looping
            # in Python, same batching approach used for the ML model.
            lookup_rows = []
            for (sens, _r), decision in DECISION_MATRIX.items():
                if _r == r_status:
                    lookup_rows.append({"Sensitivity": sens, **decision})
            lookup_df = pd.DataFrame(lookup_rows)

            df = df.merge(lookup_df, on="Sensitivity", how="left")

            # Any sensitivity value not covered by the matrix (shouldn't
            # happen given sensitivity_engine only emits HIGH/MEDIUM/LOW,
            # but fail safe rather than silently dropping rows).
            unmapped = df["algorithm"].isna().sum()
            if unmapped > 0:
                df["algorithm"] = df["algorithm"].fillna("AES-128-CBC")
                df["policy"] = df["policy"].fillna("Default Security Policy")
                df["pqc_handshake"] = df["pqc_handshake"].fillna(False)
                df["symmetric_cipher"] = df["symmetric_cipher"].fillna("AES-128-CBC")

            df["Resource_Status"] = r_status
            df["CPU_Percent"] = resource["cpu_percent"]
            df["Memory_Percent"] = resource["memory_percent"]
            df = df.rename(columns={
                "algorithm": "Selected_Algorithm",
                "policy": "Selected_Policy",
                "pqc_handshake": "PQC_Handshake_Used",
                "symmetric_cipher": "Symmetric_Cipher",
            })

            df.to_csv(self.output_file, index=False)

            execution_time = time.time() - self.start_time
            StatusManager.record_module_timing("Policy Engine", execution_time)

            policy_counts = df["Selected_Policy"].value_counts().to_dict()
            algo_counts = df["Selected_Algorithm"].value_counts().to_dict()

            message = (
                f"✓ Policy Decisions Complete | Resources: {r_status} "
                f"(CPU {resource['cpu_percent']}%, Mem {resource['memory_percent']}%) | "
                f"Policies: {policy_counts} | File: {self.output_file}"
            )

            print(f"[DEBUG] {message}")
            print(f"[DEBUG] Algorithm distribution: {algo_counts}")
            StatusManager.update_status("Policy", message, 98)
            return self.output_file

        except Exception as e:
            import traceback
            print(f"[DEBUG] Policy engine error:\n{traceback.format_exc()}")
            StatusManager.update_status("Policy", f"Error: {str(e)}")
            return None
