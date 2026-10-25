import os
import threading
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
# POLICY SETTINGS
# =====================================================================
# Resource limits, sample count, and the adaptive decision matrix are read
# from config.py so the dashboard Settings page remains the single source
# of truth. The defaults and validation for those settings belong in config.py.
#
# The policy rules expected from the configured matrix are:
#   1. HIGH sensitivity uses hybrid X25519 + ML-KEM unless the configured
#      settings explicitly allow an unsafe policy.
#   2. Every configured symmetric cipher should be an authenticated cipher
#      (AES-GCM or ChaCha20-Poly1305).
#   3. Resource status may influence the selected policy, but should not
#      silently weaken HIGH sensitivity unless the configuration permits it.
#
# STATIC_MODES are comparison baselines and intentionally do not depend on
# the resource status or adaptive decision matrix.
# =====================================================================

STATIC_MODES = {
    "static_aes": {
        "algorithm": "X25519 / AES-256-GCM",
        "policy": "Static AES-256 Policy",
        "kex": "X25519",
        "symmetric_cipher": "AES-256-GCM",
    },
    "static_pqc": {
        "algorithm": "X25519+ML-KEM-1024 / AES-256-GCM",
        "policy": "Static All-PQC Policy",
        "kex": "HYBRID_1024",
        "symmetric_cipher": "AES-256-GCM",
    },
}


def get_decision_matrix():
    """Return the current decision matrix supplied by config.py."""
    return cfgmod.decision_matrix()


def get_limits():
    """Return configured CPU threshold, memory threshold, and sample count."""
    resources = cfgmod.get("resources")
    return (
        float(resources["cpu_limit"]),
        float(resources["memory_limit"]),
        int(resources["samples"]),
    )


_PREFETCH = {"thread": None, "result": None, "started": 0.0}


def prefetch_resource_status():
    """Start the CPU/memory reading in the background (adaptive mode only).

    The reading needs about samples x 0.1 s of waiting. Starting it before feature extraction
    lets that wait overlap with real work, so the wait costs almost no extra wall-clock time.
    get_resource_status() (unforced) picks the result up automatically.
    """
    if _PREFETCH["thread"] is not None and _PREFETCH["thread"].is_alive():
        return

    def _work():
        try:
            _PREFETCH["result"] = _measure_resource_status()
        except Exception:
            _PREFETCH["result"] = None

    _PREFETCH["result"] = None
    _PREFETCH["started"] = time.time()
    t = threading.Thread(target=_work, daemon=True, name="apq-resource-prefetch")
    _PREFETCH["thread"] = t
    t.start()


def get_resource_status(force=None):
    """
    Measure the computer's resource condition for this pipeline run.

    force may be "AVAILABLE" or "CONSTRAINED" to simulate conditions in a
    demo or test. When measuring, APQCrypt's estimated CPU and resident-memory
    use are subtracted from the system readings so the pipeline's own work is
    less likely to make the machine appear busy.

    The returned cpu_percent and memory_percent represent estimated use by
    other processes. The optional cpu_total_percent and cpu_own_percent fields
    provide diagnostic context.
    """
    if force in ("AVAILABLE", "CONSTRAINED"):
        return {
            "cpu_percent": None,
            "memory_percent": None,
            "status": force,
            "reason": "forced (demo/test)",
        }

    t = _PREFETCH["thread"]
    if t is not None:                                   # a background reading was started: use it
        t.join(timeout=5)
        res, _PREFETCH["thread"], _PREFETCH["result"] = _PREFETCH["result"], None, None
        if res is not None and time.time() - _PREFETCH["started"] < 30:      # never reuse an old reading
            return res
    return _measure_resource_status()


def _measure_resource_status():
    cpu_limit, memory_limit, samples = get_limits()

    if psutil is None:
        return {
            "cpu_percent": None,
            "memory_percent": None,
            "status": "CONSTRAINED",
            "reason": "psutil not available",
        }

    # Protect against an invalid sample count in configuration.
    samples = max(1, samples)
    process = psutil.Process()
    core_count = psutil.cpu_count() or 1

    # Prime the per-process CPU counter before taking the sample window.
    process.cpu_percent(None)
    external_cpu_samples = []
    total_cpu_samples = []
    own_cpu_samples = []

    for _ in range(samples):
        total_cpu = psutil.cpu_percent(interval=0.1)
        own_cpu = process.cpu_percent(None) / core_count
        total_cpu_samples.append(total_cpu)
        own_cpu_samples.append(own_cpu)
        external_cpu_samples.append(max(0.0, total_cpu - own_cpu))

    cpu = sum(external_cpu_samples) / len(external_cpu_samples)

    virtual_memory = psutil.virtual_memory()
    own_memory_percent = (
        process.memory_info().rss / virtual_memory.total * 100
        if virtual_memory.total
        else 0.0
    )
    memory = max(0.0, virtual_memory.percent - own_memory_percent)

    status = (
        "CONSTRAINED"
        if cpu >= cpu_limit or memory >= memory_limit
        else "AVAILABLE"
    )

    return {
        "cpu_percent": round(cpu, 1),
        "memory_percent": round(memory, 1),
        "status": status,
        "cpu_total_percent": round(
            sum(total_cpu_samples) / len(total_cpu_samples), 1
        ),
        "cpu_own_percent": round(
            sum(own_cpu_samples) / len(own_cpu_samples), 1
        ),
    }


def decide(sensitivity, resource_status, mode="adaptive"):
    """
    Select a policy for one conversation/flow.

    This helper is also suitable for use by a REST endpoint. For adaptive mode,
    an unknown sensitivity/resource pair falls back to the HIGH row for the
    same resource status as a fail-safe.
    """
    if mode in STATIC_MODES:
        return dict(STATIC_MODES[mode])

    if mode != "adaptive":
        raise ValueError(f"Unknown policy mode: {mode}")

    matrix = get_decision_matrix()
    key = (str(sensitivity).upper(), str(resource_status).upper())

    if key in matrix:
        return dict(matrix[key])

    high_key = ("HIGH", str(resource_status).upper())
    if high_key not in matrix:
        raise KeyError(
            f"Decision matrix is missing required fail-safe entry {high_key}"
        )
    return dict(matrix[high_key])


class PolicyEngine:
    def __init__(self, output_file="data/policy.csv"):
        self.output_file = output_file
        self.start_time = None

    def select_policies(self, results_file, mode="adaptive", force_resource=None):
        """
        Apply policy decisions to a feature/sensitivity CSV.

        mode="adaptive"   -> decision matrix from config.py
        mode="static_aes" -> X25519 + AES-256-GCM for every row
        mode="static_pqc" -> hybrid ML-KEM-1024 + AES-256-GCM for every row

        Returns the output CSV path on success, or None on failure.
        """
        try:
            if not os.path.exists(results_file):
                message = f"Error: Results file not found: {results_file}"
                StatusManager.update_status("Policy", message)
                debuglog.log(
                    "policy",
                    "results file not found",
                    "error",
                    file=results_file,
                )
                return None

            if mode not in ("adaptive", "static_aes", "static_pqc"):
                StatusManager.update_status("Policy", f"Error: unknown mode {mode}")
                debuglog.log("policy", "unknown policy mode", "error", mode=mode)
                return None

            self.start_time = time.time()
            cpu_limit, memory_limit, samples = get_limits()

            debuglog.log(
                "policy",
                "stage_start",
                input=results_file,
                mode=mode,
                params={
                    "cpu_limit": cpu_limit,
                    "memory_limit": memory_limit,
                    "samples": samples,
                    "forced_resource": force_resource,
                },
            )

            StatusManager.update_status(
                "Policy", "Reading system resource status...", 92
            )
            resource = get_resource_status(force_resource)
            resource_status = resource["status"]

            debuglog.log(
                "policy",
                f"computer condition = {resource_status}",
                cpu_other_programs=resource["cpu_percent"],
                memory_other_programs=resource["memory_percent"],
                cpu_total=resource.get("cpu_total_percent"),
                cpu_apqcrypt=resource.get("cpu_own_percent"),
                note=resource.get("reason", "measured"),
            )

            df = pd.read_csv(results_file)
            if df.empty or "Sensitivity" not in df.columns:
                message = (
                    "Error: results file empty or 'Sensitivity' column missing"
                )
                StatusManager.update_status("Policy", message)
                debuglog.log("policy", message, "error", file=results_file)
                return None

            StatusManager.update_status(
                "Policy",
                f"Applying {mode} policy ({len(df)} rows, "
                f"resources: {resource_status})...",
                95,
            )

            if mode == "adaptive":
                matrix = get_decision_matrix()
                lookup_rows = [
                    {"Sensitivity": sensitivity, **decision}
                    for (sensitivity, condition), decision in matrix.items()
                    if str(condition).upper() == resource_status
                ]

                if not lookup_rows:
                    raise ValueError(
                        f"No decision-matrix entries for resource status "
                        f"{resource_status}"
                    )

                lookup = pd.DataFrame(lookup_rows)

                # Avoid pandas merge suffixes if the input CSV already contains
                # outputs from an earlier policy pass.
                policy_columns = [
                    "algorithm",
                    "policy",
                    "kex",
                    "symmetric_cipher",
                ]
                df = df.drop(
                    columns=[column for column in policy_columns if column in df.columns],
                    errors="ignore",
                )
                df["Sensitivity"] = df["Sensitivity"].astype(str).str.upper()
                lookup["Sensitivity"] = lookup["Sensitivity"].astype(str).str.upper()
                df = df.merge(lookup, on="Sensitivity", how="left")

                # Fail safe: missing or unrecognized sensitivity uses HIGH.
                high = matrix.get(("HIGH", resource_status))
                if high is None:
                    raise KeyError(
                        f"Decision matrix is missing HIGH/{resource_status} "
                        "fail-safe policy"
                    )
                for column in policy_columns:
                    if column not in df.columns:
                        df[column] = high[column]
                    else:
                        df[column] = df[column].fillna(high[column])
            else:
                # Baseline mode: assign the same fixed policy to every row.
                for column, value in STATIC_MODES[mode].items():
                    df[column] = value

            df["PQC_Handshake_Used"] = df["kex"].astype(str).str.startswith(
                "HYBRID"
            )
            df["Resource_Status"] = resource_status
            df["CPU_Percent"] = resource.get("cpu_percent")
            df["Memory_Percent"] = resource.get("memory_percent")
            df["Mode"] = mode
            df["Policy_Reason"] = (
                df["Sensitivity"].astype(str)
                + " + "
                + resource_status
                + " -> "
                + df["algorithm"].astype(str)
            )

            df = df.rename(
                columns={
                    "algorithm": "Selected_Algorithm",
                    "policy": "Selected_Policy",
                    "kex": "Key_Exchange",
                    "symmetric_cipher": "Symmetric_Cipher",
                }
            )

            output_directory = os.path.dirname(self.output_file)
            if output_directory:
                os.makedirs(output_directory, exist_ok=True)

            # Write to a temporary file then atomically replace the target so
            # the dashboard does not read a partially written policy CSV.
            temporary_file = self.output_file + ".tmp"
            df.to_csv(temporary_file, index=False)
            os.replace(temporary_file, self.output_file)

            elapsed_seconds = time.time() - self.start_time
            StatusManager.record_module_timing("Policy Engine", elapsed_seconds)

            policy_counts = df["Selected_Policy"].value_counts().to_dict()
            algorithm_counts = df["Selected_Algorithm"].value_counts().to_dict()
            message = (
                f"✓ Policy Decisions Complete ({mode}) | "
                f"Resources: {resource_status} "
                f"(CPU {resource.get('cpu_percent')}%, "
                f"Mem {resource.get('memory_percent')}%) | "
                f"Policies: {policy_counts} | File: {self.output_file}"
            )

            print(f"[DEBUG] {message}")
            print(f"[DEBUG] Algorithm distribution: {algorithm_counts}")
            StatusManager.update_status("Policy", message, 98)

            debuglog.log(
                "policy",
                "stage_end",
                rows_in=int(len(df)),
                rows_out=int(len(df)),
                seconds=round(elapsed_seconds, 3),
                output=self.output_file,
                resource=resource_status,
                result={key: int(value) for key, value in algorithm_counts.items()},
            )
            return self.output_file

        except Exception as error:
            import traceback

            print(f"[DEBUG] Policy engine error:\n{traceback.format_exc()}")
            StatusManager.update_status("Policy", f"Error: {str(error)}")
            debuglog.log(
                "policy",
                "policy error",
                "error",
                error=str(error)[:200],
            )
            return None
