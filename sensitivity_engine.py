import os
os.environ["PYTHONWARNINGS"] = "ignore"
import pandas as pd
import numpy as np
import pickle
import time
import os
import warnings
warnings.filterwarnings("ignore")

from status_manager import StatusManager

# Try multiple possible paths for the model
POSSIBLE_MODEL_PATHS = [
    "sensitivity_model.pkl",
    "data/sensitivity_model.pkl",
    "/app/sensitivity_model.pkl",
    os.path.expanduser("~/sensitivity_model.pkl"),
]

def find_model_path():
    """Find the model file in common locations"""
    for path in POSSIBLE_MODEL_PATHS:
        if os.path.exists(path):
            return path
    return "sensitivity_model.pkl"  # Default fallback

MODEL_PATH = find_model_path()

# ── Port-based confidentiality table (NIST SP 800-60 App. C) ──
# Score = how confidential/sensitive the data on this port typically is.
PORT_CONFIDENTIALITY = {
    22: 1.0,    # SSH
    443: 0.9,   # HTTPS
    8443: 0.9,  # HTTPS-alt
    993: 1.0,   # IMAPS
    995: 1.0,   # POP3S
    636: 1.0,   # LDAPS
    80: 0.5,    # HTTP
    8000: 0.5,  # HTTP-alt (Mininet test server port)
    25: 0.6,    # SMTP
    143: 0.6,   # IMAP
    3306: 0.7,  # MySQL
    5432: 0.7,  # Postgres
    53: 0.4,    # DNS
    123: 0.05,  # NTP
    161: 0.2,   # SNMP
    67: 0.1,    # DHCP
    68: 0.1,    # DHCP
}

# ── Protocol-based fallback for traffic with no meaningful port ──
PROTOCOL_CONFIDENTIALITY = {
    "ARP": 0.05,    # Layer-2 address resolution — no payload data
    "ICMP": 0.10,   # Ping/control messages — minimal sensitivity
    "HTTPS": 0.90,  # Encrypted web traffic
    "HTTP": 0.50,   # Plaintext web traffic
    "DNS": 0.40,    # Domain lookups
    "TCP": 0.40,    # Generic TCP
    "UDP": 0.30,    # Generic UDP
    "OTHER": 0.30,
}

TIER_TO_SCORE = {"HIGH": 0.85, "MEDIUM": 0.50, "LOW": 0.15}
SCORE_TO_TIER_THRESHOLDS = [(0.70, "HIGH"), (0.40, "MEDIUM")]

# Full 38-feature row template used per packet. Order/keys must match
# what the trained model's feature_names expect (matched by name via
# reindex, not position, so this dict's key order doesn't matter).
FEATURE_TEMPLATE_KEYS = [
    "destination port", "protocol", "flow duration",
    "total fwd packets", "total backward packets",
    "total length of fwd packets", "total length of bwd packets",
    "fwd packet length max", "fwd packet length min", "fwd packet length mean",
    "bwd packet length max", "bwd packet length min", "bwd packet length mean",
    "flow bytes/s", "flow packets/s",
    "flow iat mean", "flow iat std", "flow iat max", "flow iat min",
    "fwd iat total", "fwd iat mean", "bwd iat mean",
    "fwd psh flags", "bwd psh flags",
    "fin flag count", "syn flag count", "rst flag count",
    "psh flag count", "ack flag count", "urg flag count",
    "avg fwd segment size", "avg bwd segment size",
    "init_win_bytes_forward", "init_win_bytes_backward",
    "active mean", "idle mean",
    "subflow fwd packets", "subflow bwd packets",
]

# Map our Protocol labels to IP protocol numbers for the ML model's
# "protocol" feature (6=TCP, 17=UDP, 1=ICMP, 0=other/ARP)
PROTOCOL_NUM_MAP = {
    "TCP": 6,
    "HTTP": 6,
    "HTTPS": 6,
    "UDP": 17,
    "DNS": 17,
    "ICMP": 1,
    "ARP": 0,
    "OTHER": 0,
}


_CACHED_MODEL = None


def get_cached_model(model_path):
    """
    Load the RiskModel ONCE and reuse it across pipeline runs.
    Previously classify_sensitivity() called RiskModel(MODEL_PATH)
    fresh every single run, which re-does pickle.load() (deserializing
    the whole RandomForest -- all trees) every time. On this VM that
    alone was costing several seconds. Now it's loaded once and kept
    in memory for the lifetime of the Flask process.
    """
    global _CACHED_MODEL
    if _CACHED_MODEL is None:
        _CACHED_MODEL = RiskModel(model_path)
    return _CACHED_MODEL


def score_to_tier(score):
    for threshold, tier in SCORE_TO_TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "LOW"


class RiskModel:
    """Wraps the trained Random Forest model."""

    def __init__(self, model_path=None):
        if model_path is None:
            model_path = MODEL_PATH

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at: {model_path}\n"
                f"Tried paths: {POSSIBLE_MODEL_PATHS}"
            )

        try:
            with open(model_path, "rb") as f:
                bundle = pickle.load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load model: {str(e)}")

        # Validate bundle structure
        required_keys = ["model", "label_encoder", "feature_names", "classes"]
        missing_keys = [k for k in required_keys if k not in bundle]
        if missing_keys:
            raise ValueError(f"Model bundle missing keys: {missing_keys}")

        self.model = bundle["model"]
        self.le = bundle["label_encoder"]
        self.features = bundle["feature_names"]
        self.classes = bundle["classes"]

    def predict_batch(self, feat_df):
        """
        Vectorized replacement for the old per-row predict_row() loop.
        Builds the full (n_rows x n_features) matrix in one shot and
        calls predict()/predict_proba() ONCE for the whole batch,
        instead of once per row. This is the main fix for the
        ~98s Sensitivity Analysis bottleneck -- sklearn is built to
        score batches, not single rows in a Python for-loop.

        feat_df: DataFrame already containing the raw columns needed
                 (built by _build_feature_matrix below).
        Returns: (tiers: np.ndarray[str], confidences: np.ndarray[float])
        """
        # Reindex to the model's expected feature order/name set,
        # filling anything missing with 0 (mirrors old row_dict.get(feat, 0)).
        X = feat_df.reindex(columns=self.features, fill_value=0.0)
        X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        X = X.to_numpy(dtype=float)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        pred_enc = self.model.predict(X)
        proba = self.model.predict_proba(X)

        tiers = self.le.inverse_transform(pred_enc)
        confidences = proba.max(axis=1)

        return tiers, confidences


def _build_feature_matrix(df_in):
    """
    Vectorized construction of the 38-feature matrix for ALL rows at
    once (replaces the old per-row `row = {...}` dict built inside a
    Python for-loop). Column names match FEATURE_TEMPLATE_KEYS /
    what predict_row() used to build per row.
    """
    n = len(df_in)

    dst_port = pd.to_numeric(df_in.get("Dest_Port", 0), errors="coerce").fillna(0).astype(int)
    protocol = df_in.get("Protocol", "OTHER").astype(str)
    packet_size = pd.to_numeric(df_in.get("Packet_Length", 0), errors="coerce").fillna(0).astype(int)
    flags = df_in.get("Flags", "").astype(str)

    protocol_num = protocol.map(PROTOCOL_NUM_MAP).fillna(6).astype(int)

    has_p = flags.str.contains("P", regex=False)
    has_f = flags.str.contains("F", regex=False)
    has_s = flags.str.contains("S", regex=False)
    has_r = flags.str.contains("R", regex=False)
    has_a = flags.str.contains("A", regex=False)
    has_u = flags.str.contains("U", regex=False)

    feat_df = pd.DataFrame({
        "destination port": dst_port,
        "protocol": protocol_num,
        "flow duration": 0,
        "total fwd packets": 1,
        "total backward packets": 0,
        "total length of fwd packets": packet_size,
        "total length of bwd packets": 0,
        "fwd packet length max": packet_size,
        "fwd packet length min": packet_size,
        "fwd packet length mean": packet_size,
        "bwd packet length max": 0,
        "bwd packet length min": 0,
        "bwd packet length mean": 0,
        "flow bytes/s": 0,
        "flow packets/s": 0,
        "flow iat mean": 0,
        "flow iat std": 0,
        "flow iat max": 0,
        "flow iat min": 0,
        "fwd iat total": 0,
        "fwd iat mean": 0,
        "bwd iat mean": 0,
        "fwd psh flags": has_p.astype(int),
        "bwd psh flags": 0,
        "fin flag count": has_f.astype(int),
        "syn flag count": has_s.astype(int),
        "rst flag count": has_r.astype(int),
        "psh flag count": has_p.astype(int),
        "ack flag count": has_a.astype(int),
        "urg flag count": has_u.astype(int),
        "avg fwd segment size": packet_size,
        "avg bwd segment size": 0,
        "init_win_bytes_forward": 65535,
        "init_win_bytes_backward": 65535,
        "active mean": 0,
        "idle mean": 0,
        "subflow fwd packets": 1,
        "subflow bwd packets": 0,
    }, index=df_in.index)

    return feat_df, dst_port, protocol, packet_size


def _confidentiality_vectorized(dst_port, protocol):
    """Vectorized version of the old confidentiality_score() per-row function."""
    port_series = pd.Series(dst_port)
    port_conf = port_series.map(PORT_CONFIDENTIALITY)  # NaN where no match
    proto_conf = protocol.map(PROTOCOL_CONFIDENTIALITY).fillna(0.4)

    conf_score = port_conf.where(port_conf.notna(), proto_conf)

    port_matched = port_series.isin(PORT_CONFIDENTIALITY.keys())
    proto_matched = protocol.isin(PROTOCOL_CONFIDENTIALITY.keys())

    conf_signal = np.where(
        port_matched,
        "PORT-" + port_series.astype(str),
        np.where(proto_matched, "PROTO-" + protocol, "DEFAULT"),
    )

    return conf_score.to_numpy(dtype=float), conf_signal


def _fuse_vectorized(conf_score, risk_tier, risk_conf):
    """Vectorized version of the old fuse() per-row function.
    FINAL = MAX(Confidentiality_Score, Risk_Score)"""
    risk_tier_series = pd.Series(risk_tier)
    risk_score = risk_tier_series.map(TIER_TO_SCORE).fillna(0.5).to_numpy(dtype=float)
    risk_score = np.where(risk_conf < 0.60, risk_score * 0.7, risk_score)

    final_score = np.maximum(conf_score, risk_score)
    final_tier = np.select(
        [final_score >= 0.70, final_score >= 0.40],
        ["HIGH", "MEDIUM"],
        default="LOW",
    )
    return final_tier, np.round(final_score, 3)


class SensitivityEngine:
    def __init__(self):
        self.output_file = "data/results.csv"
        self.start_time = None

    def classify_sensitivity(self, feature_file):
        """
        Reads the extracted features CSV, runs the hybrid
        Confidentiality (port + protocol) + Risk (ML model) scoring
        on ALL rows at once (vectorized), and writes results.csv
        with full breakdown.

        NOTE: This replaces the old per-row `for idx, row in
        df_in.iterrows(): ... risk_model.predict_packet(...)` loop,
        which called the sklearn model twice (predict + predict_proba)
        PER ROW. That was the ~98s bottleneck for 210 packets. This
        version calls the model exactly once for the whole batch.
        """
        try:
            if not os.path.exists(feature_file):
                StatusManager.update_status("Sensitivity", f"Error: Feature file not found: {feature_file}")
                return None

            self.start_time = time.time()
            StatusManager.update_status("Sensitivity", "Loading sensitivity model...", 75)

            try:
                risk_model = get_cached_model(MODEL_PATH)
            except FileNotFoundError as e:
                error_msg = f"Model not found: {str(e)}"
                print(f"[DEBUG] {error_msg}")
                StatusManager.update_status("Sensitivity", error_msg)
                return None
            except Exception as e:
                error_msg = f"Failed to load model: {str(e)}"
                print(f"[DEBUG] {error_msg}")
                StatusManager.update_status("Sensitivity", error_msg)
                return None

            try:
                df_in = pd.read_csv(feature_file)
            except Exception as e:
                error_msg = f"Failed to read features file: {str(e)}"
                StatusManager.update_status("Sensitivity", error_msg)
                return None

            if len(df_in) == 0:
                StatusManager.update_status("Sensitivity", "Error: Features file is empty")
                return None

            StatusManager.update_status(
                "Sensitivity",
                f"Analyzing {len(df_in)} packets (Confidentiality + Risk scoring, batched)...",
                80
            )

            try:
                # ---- Build full feature matrix for ALL rows at once ----
                feat_df, dst_port, protocol, packet_size = _build_feature_matrix(df_in)

                # ---- Confidentiality: pure port + protocol (vectorized) ----
                conf_score, conf_signal = _confidentiality_vectorized(dst_port, protocol)

                # ---- Risk: ML model on packet-level features, ONE batched call ----
                risk_tier, risk_conf = risk_model.predict_batch(feat_df)

                # ---- Fuse (vectorized) ----
                final_tier, final_score = _fuse_vectorized(conf_score, risk_tier, risk_conf)

                out = pd.DataFrame({
                    "Source_IP": df_in.get("Source_IP", "NA"),
                    "Destination_IP": df_in.get("Destination_IP", "NA"),
                    "Source_Port": df_in.get("Source_Port", 0),
                    "Dest_Port": dst_port,
                    "Protocol": protocol,
                    "Packet_Length": packet_size,
                    "TTL": pd.to_numeric(df_in.get("TTL", 0), errors="coerce").fillna(0).astype(int),
                    "Confidentiality_Score": np.round(conf_score, 3),
                    "Confidentiality_Signal": conf_signal,
                    "Risk_Tier": risk_tier,
                    "Risk_Confidence": np.round(risk_conf, 3),
                    "Sensitivity": final_tier,
                    "Final_Score": final_score,
                })

            except Exception as e:
                import traceback
                print(f"[DEBUG] Batch sensitivity scoring error:\n{traceback.format_exc()}")
                error_msg = f"Error: {str(e)}"
                StatusManager.update_status("Sensitivity", error_msg)
                return None

            if len(out) == 0:
                error_msg = "Error: No rows processed"
                StatusManager.update_status("Sensitivity", error_msg)
                return None

            out.to_csv(self.output_file, index=False)

            execution_time = time.time() - self.start_time
            StatusManager.record_module_timing("Sensitivity Analysis", execution_time)

            sensitivity_counts = out["Sensitivity"].value_counts().to_dict()

            message = (
                f"✓ Sensitivity Analysis Complete | "
                f"HIGH: {sensitivity_counts.get('HIGH', 0)}, "
                f"MEDIUM: {sensitivity_counts.get('MEDIUM', 0)}, "
                f"LOW: {sensitivity_counts.get('LOW', 0)} | "
                f"File: {self.output_file}"
            )

            StatusManager.update_status("Sensitivity", message, 90)
            return self.output_file

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"[DEBUG] Sensitivity engine error:\n{error_trace}")
            StatusManager.update_status("Sensitivity", f"Error: {str(e)}")
            return None
