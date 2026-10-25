import os
os.environ["PYTHONWARNINGS"] = "ignore"
import pandas as pd
import numpy as np
import pickle
import time
import warnings
warnings.filterwarnings("ignore")

from status_manager import StatusManager

POSSIBLE_MODEL_PATHS = [
    "sensitivity_model.pkl",
    "data/sensitivity_model.pkl",
    "/app/sensitivity_model.pkl",
    os.path.expanduser("~/sensitivity_model.pkl"),
]


def find_model_path():
    for path in POSSIBLE_MODEL_PATHS:
        if os.path.exists(path):
            return path
    return "sensitivity_model.pkl"


MODEL_PATH = find_model_path()

# =====================================================================
#  SETTINGS (all the numbers in one place -- easy to explain and change)
# =====================================================================
# Confidentiality scores are OUR expert-assigned values. They are INFORMED BY
# NIST FIPS 199 (Low/Moderate/High idea) and NIST SP 800-60 (information
# types). Neither standard defines port numbers or these exact scores.
PORT_CONFIDENTIALITY = {
    22: 1.0, 443: 0.9, 8443: 0.9, 993: 1.0, 995: 1.0, 636: 1.0,
    80: 0.5, 8000: 0.5, 25: 0.6, 143: 0.6, 3306: 0.7, 5432: 0.7,
    53: 0.4, 123: 0.05, 161: 0.2, 67: 0.1, 68: 0.1,
}
PROTOCOL_CONFIDENTIALITY = {
    "ARP": 0.05, "ICMP": 0.10, "HTTPS": 0.90, "HTTP": 0.50, "SSH": 1.0,
    "DNS": 0.40, "NTP": 0.05, "TCP": 0.40, "UDP": 0.30, "OTHER": 0.30,
}
TIER_TO_SCORE = {"HIGH": 0.85, "MEDIUM": 0.50, "LOW": 0.15}
SCORE_TO_TIER_THRESHOLDS = [(0.70, "HIGH"), (0.40, "MEDIUM")]

# "Peek" rules (DPI on first bytes only; headers/names that are plaintext by design)
SENSITIVE_NAME_WORDS = ["bank", "pay", "health", "hospital", "clinic", "gov",
                        "secure", "login", "account", "wallet", "tax"]

# If the AI model is unsure, we RAISE protection (never lower it).
UNCERTAIN_CONF = 0.60
UNCERTAIN_FLOOR = 0.50
RAISE_WHEN_UNCERTAIN = True

# One decision per conversation: highest score seen in its first N packets.
FLOW_FIRST_N = 10

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

PROTOCOL_NUM_MAP = {"TCP": 6, "HTTP": 6, "HTTPS": 6, "SSH": 6, "UDP": 17, "DNS": 17,
                    "NTP": 17, "ICMP": 1, "ARP": 0, "OTHER": 0}

_CACHED_MODEL = None


def get_cached_model(model_path):
    global _CACHED_MODEL
    if _CACHED_MODEL is None:
        _CACHED_MODEL = RiskModel(model_path)
    return _CACHED_MODEL


def score_to_tier(score):
    for threshold, tier in SCORE_TO_TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "LOW"


# =====================================================================
#  "PEEK" PARSERS (read plaintext headers from the first payload bytes)
# =====================================================================
def _hex_to_bytes(h):
    try:
        return bytes.fromhex(h) if isinstance(h, str) and h else b""
    except ValueError:
        return b""


def parse_tls_sni(p):
    """Website name from a TLS ClientHello (RFC 6066: SNI is sent in plain text)."""
    try:
        if len(p) < 6 or p[0] != 0x16 or p[5] != 0x01:
            return None
        i = 5 + 4 + 2 + 32                       # record hdr + handshake hdr + version + random
        i += 1 + p[i]                            # session id
        i += 2 + int.from_bytes(p[i:i + 2], "big")   # cipher suites
        i += 1 + p[i]                            # compression methods
        ext_total = int.from_bytes(p[i:i + 2], "big")
        i += 2
        end = min(len(p), i + ext_total)
        while i + 4 <= end:
            et = int.from_bytes(p[i:i + 2], "big")
            el = int.from_bytes(p[i + 2:i + 4], "big")
            i += 4
            if et == 0:                          # server_name extension
                nl = int.from_bytes(p[i + 3:i + 5], "big")
                return p[i + 5:i + 5 + nl].decode("ascii", "ignore").lower()
            i += el
    except Exception:
        return None
    return None


def parse_dns_query(p):
    """(name, qtype) from a DNS message (RFC 1035 wire format)."""
    try:
        if len(p) < 17:
            return None
        i, labels = 12, []
        while True:
            ln = p[i]
            i += 1
            if ln == 0:
                break
            if ln & 0xC0:
                return None
            labels.append(p[i:i + ln].decode("ascii", "ignore"))
            i += ln
        qtype = int.from_bytes(p[i:i + 2], "big")
        return ".".join(labels).lower(), qtype
    except Exception:
        return None


def parse_http_request(p):
    """(method, has_auth_or_cookie) from a plain HTTP request (RFC 7230)."""
    try:
        head = p[:512].split(b"\r\n\r\n")[0].decode("latin-1")
        method = head.split("\r\n")[0].split(" ")[0]
        if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"):
            return None
        low = head.lower()
        return method, ("authorization:" in low or "cookie:" in low)
    except Exception:
        return None


def dpi_signal(payload, protocol=""):
    """Returns (score_or_nan, text). Score only RAISES confidentiality."""
    if not payload:
        return np.nan, ""
    name = parse_tls_sni(payload)
    if name:
        if any(w in name for w in SENSITIVE_NAME_WORDS):
            return 1.0, f"SNI:{name}(sensitive)"
        return np.nan, f"SNI:{name}"
    if payload.startswith(b"SSH-2.0-") or payload.startswith(b"SSH-1."):
        return 1.0, "SSH-banner"
    http = parse_http_request(payload)
    if http:
        method, auth = http
        if method in ("POST", "PUT") and auth:
            return 1.0, f"HTTP-{method}+auth"
        if auth:
            return 0.9, f"HTTP-{method}+auth"
        if method in ("POST", "PUT"):
            return 0.7, f"HTTP-{method}"
        return np.nan, f"HTTP-{method}"
    dns = parse_dns_query(payload) if protocol == "DNS" else None   # only try DNS on DNS traffic
    if dns and dns[0]:
        qname, qtype = dns
        if qtype in (15, 16):                    # MX / TXT
            return 0.8, f"DNS-{'MX' if qtype == 15 else 'TXT'}:{qname}"
        return np.nan, f"DNS:{qname}"
    return np.nan, ""


class RiskModel:
    """Wraps the trained Random Forest model.

    Two ways to load the SAME trained forest:
      * sensitivity_model_lite.npz (numpy only, small, fast)  <- used automatically when the file exists
      * sensitivity_model.pkl      (scikit-learn pickle)      <- fallback
    Create the .npz once with:  python compact_model.py convert sensitivity_model.pkl
    """

    def __init__(self, model_path=None):
        if model_path is None:
            model_path = MODEL_PATH
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at: {model_path}\nTried paths: {POSSIBLE_MODEL_PATHS}")

        lite_path = os.path.join(os.path.dirname(os.path.abspath(model_path)), "sensitivity_model_lite.npz")
        self.loader = None
        if os.path.exists(lite_path) and not os.environ.get("APQ_NO_COMPACT"):
            try:
                from compact_model import CompactForest, CompactLabels
                forest, names, label_classes = CompactForest.load(lite_path)
                self.model = forest
                self.le = CompactLabels(label_classes)
                self.features = names
                self.classes = list(label_classes)
                self.loader = "compact (numpy, no scikit-learn)"
            except Exception as e:                      # a bad compact file must never stop the pipeline
                print(f"[APQCrypt] compact model not used ({e}); falling back to the pickle")
                self.loader = None
        if self.loader is None:
            try:
                with open(model_path, "rb") as f:
                    bundle = pickle.load(f)
            except Exception as e:
                raise RuntimeError(f"Failed to load model: {str(e)}")
            missing = [k for k in ["model", "label_encoder", "feature_names", "classes"] if k not in bundle]
            if missing:
                raise ValueError(f"Model bundle missing keys: {missing}")
            self.model = bundle["model"]
            self.le = bundle["label_encoder"]
            self.features = bundle["feature_names"]
            self.classes = bundle["classes"]
            self.loader = "pickle (scikit-learn)"

    def predict_batch(self, feat_df):
        X = feat_df.reindex(columns=self.features, fill_value=0.0)
        X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        X = np.nan_to_num(X.to_numpy(dtype=float), nan=0.0, posinf=0.0, neginf=0.0)
        # Many packets have identical features (same size, port, flags). Run the forest only on the
        # distinct rows and copy the answer back: identical input -> identical output, so the result
        # is exactly the same, with far less work.
        Xu, inv = np.unique(X, axis=0, return_inverse=True)
        inv = np.asarray(inv).reshape(-1)
        proba_u = self.model.predict_proba(Xu)                    # walk the forest ONCE, distinct rows only
        proba = proba_u[inv]
        pred_enc = self.model.classes_[proba.argmax(axis=1)]      # same answer predict() would give
        return self.le.inverse_transform(pred_enc), proba.max(axis=1)


def _build_feature_matrix(df_in):
    """
    NOTE (honest limitation): the model was trained on whole-conversation
    features. Here each packet is treated as a tiny conversation, so most
    timing/count features are 0 or 1. TCP flags and window are now REAL.
    Say this clearly in the paper (future work: real flow features).
    """
    idx = df_in.index
    dst_port = pd.to_numeric(df_in.get("Dest_Port", 0), errors="coerce").fillna(0).astype(int)
    protocol = df_in.get("Protocol", pd.Series("OTHER", index=idx)).astype(str)
    packet_size = pd.to_numeric(df_in.get("Packet_Length", 0), errors="coerce").fillna(0).astype(int)

    if "TCP_Flags" in df_in.columns:
        flags = df_in["TCP_Flags"].fillna("").astype(str)
    else:
        flags = pd.Series([""] * len(df_in), index=idx)   # old features file: no flags known

    win = pd.to_numeric(df_in["Window"], errors="coerce").fillna(0) if "Window" in df_in.columns \
        else pd.Series(0, index=idx)
    win = win.where(win > 0, 65535).astype(int)

    protocol_num = protocol.map(PROTOCOL_NUM_MAP).fillna(6).astype(int)
    has = lambda ch: flags.str.contains(ch, regex=False).astype(int)
    p_, f_, s_, r_, a_, u_ = has("P"), has("F"), has("S"), has("R"), has("A"), has("U")

    feat_df = pd.DataFrame({
        "destination port": dst_port, "protocol": protocol_num, "flow duration": 0,
        "total fwd packets": 1, "total backward packets": 0,
        "total length of fwd packets": packet_size, "total length of bwd packets": 0,
        "fwd packet length max": packet_size, "fwd packet length min": packet_size,
        "fwd packet length mean": packet_size,
        "bwd packet length max": 0, "bwd packet length min": 0, "bwd packet length mean": 0,
        "flow bytes/s": 0, "flow packets/s": 0,
        "flow iat mean": 0, "flow iat std": 0, "flow iat max": 0, "flow iat min": 0,
        "fwd iat total": 0, "fwd iat mean": 0, "bwd iat mean": 0,
        "fwd psh flags": p_, "bwd psh flags": 0,
        "fin flag count": f_, "syn flag count": s_, "rst flag count": r_,
        "psh flag count": p_, "ack flag count": a_, "urg flag count": u_,
        "avg fwd segment size": packet_size, "avg bwd segment size": 0,
        "init_win_bytes_forward": win, "init_win_bytes_backward": 65535,
        "active mean": 0, "idle mean": 0, "subflow fwd packets": 1, "subflow bwd packets": 0,
    }, index=idx)
    return feat_df, dst_port, protocol, packet_size


def _confidentiality_vectorized(df_in, protocol):
    """Port + protocol score. Looks at BOTH ports so the reply direction scores the same."""
    idx = df_in.index
    dst = pd.to_numeric(df_in.get("Dest_Port", 0), errors="coerce").fillna(0).astype(int)
    src = pd.to_numeric(df_in.get("Source_Port", 0), errors="coerce").fillna(0).astype(int)
    known = set(PORT_CONFIDENTIALITY.keys())
    dst_known, src_known = dst.isin(known), src.isin(known)
    svc_port = dst.where(dst_known, src.where(src_known, dst))   # the "service" port

    port_conf = svc_port.map(PORT_CONFIDENTIALITY)
    proto_conf = protocol.map(PROTOCOL_CONFIDENTIALITY).fillna(0.4)
    conf = port_conf.where(port_conf.notna(), proto_conf)

    signal = np.where(svc_port.isin(known), "PORT-" + svc_port.astype(str),
                      np.where(protocol.isin(PROTOCOL_CONFIDENTIALITY.keys()), "PROTO-" + protocol, "DEFAULT"))
    return conf.to_numpy(dtype=float), signal, svc_port


class SensitivityEngine:
    def __init__(self):
        self.output_file = "data/results.csv"
        self.start_time = None

    def classify_sensitivity(self, feature_file):
        try:
            if not os.path.exists(feature_file):
                StatusManager.update_status("Sensitivity", f"Error: Feature file not found: {feature_file}")
                return None

            self.start_time = time.time()
            StatusManager.update_status("Sensitivity", "Loading sensitivity model...", 75)
            try:
                risk_model = get_cached_model(MODEL_PATH)
            except Exception as e:
                StatusManager.update_status("Sensitivity", f"Model error: {str(e)}")
                return None

            try:
                df_in = pd.read_csv(feature_file)
            except Exception as e:
                StatusManager.update_status("Sensitivity", f"Failed to read features file: {str(e)}")
                return None
            if len(df_in) == 0:
                StatusManager.update_status("Sensitivity", "Error: Features file is empty")
                return None

            StatusManager.update_status("Sensitivity", f"Analyzing {len(df_in)} packets...", 80)

            try:
                feat_df, dst_port, protocol, packet_size = _build_feature_matrix(df_in)

                # ---- Dimension 1: Confidentiality (port/protocol + peek) ----
                conf_base, conf_signal, _svc = _confidentiality_vectorized(df_in, protocol)

                if "First_Bytes_Hex" in df_in.columns:
                    payloads = [_hex_to_bytes(h) for h in df_in["First_Bytes_Hex"].fillna("")]
                    dpi = [dpi_signal(p, pr) for p, pr in zip(payloads, protocol)]
                    dpi_score = np.array([d[0] for d in dpi], dtype=float)
                    dpi_text = np.array([d[1] for d in dpi], dtype=object)
                else:
                    dpi_score = np.full(len(df_in), np.nan)
                    dpi_text = np.array([""] * len(df_in), dtype=object)

                conf_score = np.where(np.isnan(dpi_score), conf_base, np.maximum(conf_base, dpi_score))

                # ---- Dimension 2: Behavioural risk (ML, ONE batched call) ----
                risk_tier, risk_conf = risk_model.predict_batch(feat_df)
                risk_score = pd.Series(risk_tier).map(TIER_TO_SCORE).fillna(0.5).to_numpy(dtype=float)
                uncertain = risk_conf < UNCERTAIN_CONF
                if RAISE_WHEN_UNCERTAIN:
                    risk_score = np.where(uncertain, np.maximum(risk_score, UNCERTAIN_FLOOR), risk_score)
                n_unc = int(uncertain.sum())
                print(f"[DEBUG] Uncertain model rows: {n_unc}/{len(df_in)} ({100 * n_unc / len(df_in):.0f}%). "
                      f"If this is very high the model sees unfamiliar data (see limits in report).")

                # ---- Fuse: MAX ----
                packet_score = np.maximum(conf_score, risk_score)

                # ---- One decision per conversation (max over first N packets) ----
                if "Flow_ID" in df_in.columns:
                    s = pd.Series(packet_score, index=df_in.index)
                    order = df_in.groupby("Flow_ID").cumcount()
                    final_score = s.where(order < FLOW_FIRST_N).groupby(df_in["Flow_ID"]).transform("max")
                    final_score = final_score.fillna(s).to_numpy(dtype=float)
                else:
                    final_score = packet_score

                final_tier = np.select([final_score >= 0.70, final_score >= 0.40], ["HIGH", "MEDIUM"], default="LOW")

                reasons = [
                    f"{cs}={cb:.2f}" + (f"; {dt}" if dt else "") +
                    f"; risk={rt}@{rc:.2f}" + ("(unsure->raised)" if (u and RAISE_WHEN_UNCERTAIN) else "") +
                    f"; flow-max={fs:.2f}"
                    for cs, cb, dt, rt, rc, u, fs in zip(conf_signal, conf_score, dpi_text, risk_tier,
                                                         risk_conf, uncertain, final_score)
                ]

                out = pd.DataFrame({
                    "Pkt_Index": df_in["Pkt_Index"] if "Pkt_Index" in df_in.columns else np.arange(len(df_in)),
                    "Flow_ID": df_in["Flow_ID"] if "Flow_ID" in df_in.columns else "NA",
                    "Source_IP": df_in.get("Source_IP", "NA"),
                    "Destination_IP": df_in.get("Destination_IP", "NA"),
                    "Source_Port": df_in.get("Source_Port", 0),
                    "Dest_Port": dst_port,
                    "Protocol": protocol,
                    "Packet_Length": packet_size,
                    "TTL": pd.to_numeric(df_in.get("TTL", 0), errors="coerce").fillna(0).astype(int),
                    "Confidentiality_Score": np.round(conf_score, 3),
                    "Confidentiality_Signal": conf_signal,
                    "DPI_Signal": dpi_text,
                    "Risk_Tier": risk_tier,
                    "Risk_Confidence": np.round(risk_conf, 3),
                    "Packet_Score": np.round(packet_score, 3),
                    "Final_Score": np.round(final_score, 3),
                    "Sensitivity": final_tier,
                    "Reason": reasons,
                })
            except Exception:
                import traceback
                print(f"[DEBUG] Scoring error:\n{traceback.format_exc()}")
                StatusManager.update_status("Sensitivity", "Error during scoring (see terminal)")
                return None

            tmp = self.output_file + ".tmp"
            out.to_csv(tmp, index=False)
            os.replace(tmp, self.output_file)

            StatusManager.record_module_timing("Sensitivity Analysis", time.time() - self.start_time)
            c = out["Sensitivity"].value_counts().to_dict()
            msg = (f"✓ Sensitivity Analysis Complete | HIGH: {c.get('HIGH', 0)}, MEDIUM: {c.get('MEDIUM', 0)}, "
                   f"LOW: {c.get('LOW', 0)} | File: {self.output_file}")
            StatusManager.update_status("Sensitivity", msg, 90)
            return self.output_file

        except Exception as e:
            import traceback
            print(f"[DEBUG] Sensitivity engine error:\n{traceback.format_exc()}")
            StatusManager.update_status("Sensitivity", f"Error: {str(e)}")
            return None
