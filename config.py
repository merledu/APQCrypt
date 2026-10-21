"""
APQCrypt configuration (the data behind the Settings page).

* DEFAULTS are the design values. The user's changes are saved in data/config.json.
* Every engine reads the settings at the START of each run, so a change on the Settings
  page applies to the next run (no code editing, no restart).
* Every value is checked before it is saved (see validate()).
* A copy of the settings used is saved with each run (data/run_config.json).
"""
import copy
import json
import os
import re
import threading
import time

CONFIG_FILE = os.environ.get("APQ_CONFIG", "data/config.json")
_lock = threading.RLock()
_cache = {"mtime": None, "cfg": None}

KEX_CHOICES = ["X25519", "HYBRID_768", "HYBRID_1024"]
CIPHER_CHOICES = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]
SENS = ["HIGH", "MEDIUM", "LOW"]
RES = ["AVAILABLE", "CONSTRAINED"]
PROTOCOLS = ["ARP", "ICMP", "HTTPS", "HTTP", "SSH", "DNS", "NTP", "TCP", "UDP", "OTHER"]
PACKET_SOURCES = ["mininet", "pcap_file"]
CRYPTO_PROVIDERS = ["liboqs", "simulated"]

DEFAULTS = {
    "capture": {"target_packets": 1000, "n_http": 60, "n_https": 40, "n_dns": 150, "n_udp": 150, "ping_count": 40},
    "scoring": {
        # Port scores are OUR design values, informed by NIST FIPS 199 / SP 800-60 (not defined by them).
        "port_scores": {"22": 1.0, "443": 0.9, "8443": 0.9, "993": 1.0, "995": 1.0, "636": 1.0,
                        "80": 0.5, "8000": 0.5, "25": 0.6, "143": 0.6, "3306": 0.7, "5432": 0.7,
                        "53": 0.4, "123": 0.05, "161": 0.2, "67": 0.1, "68": 0.1},
        "protocol_scores": {"ARP": 0.05, "ICMP": 0.10, "HTTPS": 0.90, "HTTP": 0.50, "SSH": 1.0,
                            "DNS": 0.40, "NTP": 0.05, "TCP": 0.40, "UDP": 0.30, "OTHER": 0.30},
        "sensitive_words": ["bank", "pay", "health", "hospital", "clinic", "gov",
                            "secure", "login", "account", "wallet", "tax"],
        "use_peek": True,
        "high_threshold": 0.70,
        "medium_threshold": 0.40,
        "risk_tier_scores": {"HIGH": 0.85, "MEDIUM": 0.50, "LOW": 0.15},
        "raise_when_uncertain": True,
        "uncertain_confidence": 0.60,
        "uncertain_floor": 0.50,
        "flow_first_n": 10,
    },
    "resources": {"cpu_limit": 50.0, "memory_limit": 70.0, "samples": 5},
    "policy": {
        "allow_unsafe": False,
        "matrix": {
            "HIGH":   {"AVAILABLE": {"kex": "HYBRID_1024", "cipher": "AES-256-GCM"},
                       "CONSTRAINED": {"kex": "HYBRID_1024", "cipher": "ChaCha20-Poly1305"}},
            "MEDIUM": {"AVAILABLE": {"kex": "HYBRID_768", "cipher": "AES-256-GCM"},
                       "CONSTRAINED": {"kex": "X25519", "cipher": "ChaCha20-Poly1305"}},
            "LOW":    {"AVAILABLE": {"kex": "X25519", "cipher": "AES-128-GCM"},
                       "CONSTRAINED": {"kex": "X25519", "cipher": "ChaCha20-Poly1305"}},
        },
    },
    "interfaces": {"packet_source": "mininet", "pcap_path": "data/traffic.pcapng", "crypto_provider": "liboqs"},
    "benchmark": {"runs": 5},
}


def _cell(kex, cipher):
    return {"kex": kex, "cipher": cipher}


PRESETS = {
    "balanced": {
        "title": "Balanced (default)",
        "about": "The design values: quantum-safe for HIGH always, cheaper options when the computer is busy.",
        "patch": {},
    },
    "iot_low_power": {
        "title": "IoT low power",
        "about": "For small devices. Lower busy limits and cheaper locks. HIGH still keeps quantum-safe key exchange.",
        "patch": {
            "resources": {"cpu_limit": 30.0, "memory_limit": 50.0, "samples": 3},
            "scoring": {"flow_first_n": 5},
            "policy": {"matrix": {
                "HIGH": {"AVAILABLE": _cell("HYBRID_1024", "ChaCha20-Poly1305"), "CONSTRAINED": _cell("HYBRID_1024", "ChaCha20-Poly1305")},
                "MEDIUM": {"AVAILABLE": _cell("X25519", "ChaCha20-Poly1305"), "CONSTRAINED": _cell("X25519", "ChaCha20-Poly1305")},
                "LOW": {"AVAILABLE": _cell("X25519", "ChaCha20-Poly1305"), "CONSTRAINED": _cell("X25519", "ChaCha20-Poly1305")},
            }},
        },
    },
    "high_security": {
        "title": "High security",
        "about": "Lower score limits so more traffic counts as sensitive, and stronger options everywhere.",
        "patch": {
            "resources": {"cpu_limit": 80.0, "memory_limit": 85.0},
            "scoring": {"high_threshold": 0.60, "medium_threshold": 0.30},
            "policy": {"matrix": {
                "HIGH": {"AVAILABLE": _cell("HYBRID_1024", "AES-256-GCM"), "CONSTRAINED": _cell("HYBRID_1024", "AES-256-GCM")},
                "MEDIUM": {"AVAILABLE": _cell("HYBRID_1024", "AES-256-GCM"), "CONSTRAINED": _cell("HYBRID_1024", "AES-256-GCM")},
                "LOW": {"AVAILABLE": _cell("X25519", "AES-256-GCM"), "CONSTRAINED": _cell("X25519", "AES-256-GCM")},
            }},
        },
    },
}


class ConfigError(Exception):
    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


def deep_merge(base, patch):
    out = copy.deepcopy(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


# ---------------------------------------------------------------- validation
def _num(v, lo, hi, name, errors, integer=False):
    try:
        if isinstance(v, bool):
            raise ValueError
        x = int(v) if integer else float(v)
        if integer and float(v) != x:
            raise ValueError
    except (TypeError, ValueError):
        errors.append(f"{name}: must be a {'whole ' if integer else ''}number")
        return None
    if not (lo <= x <= hi):
        errors.append(f"{name}: must be between {lo} and {hi}")
        return None
    return x


def clean(raw):
    """Keep only known keys, fix types, and collect every problem. Returns (cleaned, errors)."""
    errors = []
    raw = raw if isinstance(raw, dict) else {}
    out = copy.deepcopy(DEFAULTS)

    c = raw.get("capture", {})
    for key, (lo, hi) in {"target_packets": (50, 20000), "n_http": (0, 2000), "n_https": (0, 2000),
                          "n_dns": (0, 2000), "n_udp": (0, 2000), "ping_count": (0, 500)}.items():
        if key in c:
            v = _num(c[key], lo, hi, f"capture.{key}", errors, True)
            if v is not None:
                out["capture"][key] = v

    s = raw.get("scoring", {})
    o = out["scoring"]
    if "port_scores" in s:
        ps = {}
        if not isinstance(s["port_scores"], dict) or len(s["port_scores"]) > 200:
            errors.append("scoring.port_scores: must be a list of at most 200 ports")
        else:
            for p, sc in s["port_scores"].items():
                port = _num(p, 1, 65535, f"scoring.port_scores port '{p}'", errors, True)
                score = _num(sc, 0, 1, f"scoring.port_scores[{p}]", errors)
                if port is not None and score is not None:
                    ps[str(port)] = score
            if ps:
                o["port_scores"] = ps
    if "protocol_scores" in s:
        if not isinstance(s["protocol_scores"], dict):
            errors.append("scoring.protocol_scores: invalid")
        else:
            for p, sc in s["protocol_scores"].items():
                if p not in PROTOCOLS:
                    continue
                score = _num(sc, 0, 1, f"scoring.protocol_scores[{p}]", errors)
                if score is not None:
                    o["protocol_scores"][p] = score
    if "sensitive_words" in s:
        words = s["sensitive_words"]
        if isinstance(words, str):
            words = [w for w in re.split(r"[,\n ]+", words) if w]
        if not isinstance(words, list) or len(words) > 50:
            errors.append("scoring.sensitive_words: at most 50 words")
        else:
            good = []
            for w in words:
                w = str(w).strip().lower()
                if not re.fullmatch(r"[a-z0-9.\-]{1,40}", w):
                    errors.append(f"scoring.sensitive_words: '{w}' must be 1-40 letters, digits, dot or dash")
                else:
                    good.append(w)
            o["sensitive_words"] = good
    for key in ("use_peek", "raise_when_uncertain"):
        if key in s:
            o[key] = bool(s[key])
    hi_t = _num(s.get("high_threshold", o["high_threshold"]), 0.01, 1, "scoring.high_threshold", errors)
    med_t = _num(s.get("medium_threshold", o["medium_threshold"]), 0.01, 1, "scoring.medium_threshold", errors)
    if hi_t is not None and med_t is not None:
        if med_t >= hi_t:
            errors.append("scoring: medium_threshold must be lower than high_threshold")
        else:
            o["high_threshold"], o["medium_threshold"] = hi_t, med_t
    if "risk_tier_scores" in s and isinstance(s["risk_tier_scores"], dict):
        for t in SENS:
            if t in s["risk_tier_scores"]:
                v = _num(s["risk_tier_scores"][t], 0, 1, f"scoring.risk_tier_scores[{t}]", errors)
                if v is not None:
                    o["risk_tier_scores"][t] = v
    for key in ("uncertain_confidence", "uncertain_floor"):
        if key in s:
            v = _num(s[key], 0, 1, f"scoring.{key}", errors)
            if v is not None:
                o[key] = v
    if "flow_first_n" in s:
        v = _num(s["flow_first_n"], 1, 200, "scoring.flow_first_n", errors, True)
        if v is not None:
            o["flow_first_n"] = v

    r = raw.get("resources", {})
    for key, (lo, hi, integer) in {"cpu_limit": (5, 100, False), "memory_limit": (5, 100, False), "samples": (1, 20, True)}.items():
        if key in r:
            v = _num(r[key], lo, hi, f"resources.{key}", errors, integer)
            if v is not None:
                out["resources"][key] = v

    p = raw.get("policy", {})
    allow_unsafe = bool(p.get("allow_unsafe", False))
    out["policy"]["allow_unsafe"] = allow_unsafe
    m = p.get("matrix", {})
    for sens in SENS:
        for res in RES:
            cell = (m.get(sens) or {}).get(res)
            if cell is None:
                continue
            kex, cipher = (cell or {}).get("kex"), (cell or {}).get("cipher")
            if kex not in KEX_CHOICES:
                errors.append(f"policy.matrix[{sens}][{res}].kex: choose one of {KEX_CHOICES}")
                continue
            if cipher not in CIPHER_CHOICES:
                errors.append(f"policy.matrix[{sens}][{res}].cipher: only tamper-detecting locks are allowed: {CIPHER_CHOICES}")
                continue
            out["policy"]["matrix"][sens][res] = {"kex": kex, "cipher": cipher}
    if not allow_unsafe:
        for res in RES:
            if not out["policy"]["matrix"]["HIGH"][res]["kex"].startswith("HYBRID"):
                errors.append(f"policy.matrix[HIGH][{res}]: HIGH must use a quantum-safe (hybrid) key exchange. "
                              "Tick 'Allow unsafe settings' to override it for an experiment.")

    i = raw.get("interfaces", {})
    if "packet_source" in i:
        if i["packet_source"] in PACKET_SOURCES:
            out["interfaces"]["packet_source"] = i["packet_source"]
        else:
            errors.append(f"interfaces.packet_source: choose one of {PACKET_SOURCES}")
    if "crypto_provider" in i:
        if i["crypto_provider"] in CRYPTO_PROVIDERS:
            out["interfaces"]["crypto_provider"] = i["crypto_provider"]
        else:
            errors.append(f"interfaces.crypto_provider: choose one of {CRYPTO_PROVIDERS}")
    if "pcap_path" in i:
        path = str(i["pcap_path"]).strip()
        base = os.path.realpath(os.getcwd())
        real = os.path.realpath(path)
        if not path or "\x00" in path or len(path) > 300 or not (real == base or real.startswith(base + os.sep)):
            errors.append("interfaces.pcap_path: must be a file inside the project folder")
        else:
            out["interfaces"]["pcap_path"] = path

    b = raw.get("benchmark", {})
    if "runs" in b:
        v = _num(b["runs"], 1, 20, "benchmark.runs", errors, True)
        if v is not None:
            out["benchmark"]["runs"] = v
    return out, errors


# ---------------------------------------------------------------- load / save
def _read_file():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def get_all():
    """Effective settings (defaults + saved changes). Always valid; falls back to defaults."""
    with _lock:
        try:
            mtime = os.path.getmtime(CONFIG_FILE)
        except OSError:
            mtime = None
        if _cache["cfg"] is not None and _cache["mtime"] == mtime:
            return copy.deepcopy(_cache["cfg"])
        file_cfg = _read_file() if mtime else {}
        merged = deep_merge(DEFAULTS, file_cfg)
        saved_ports = (file_cfg.get("scoring") or {}).get("port_scores")
        if isinstance(saved_ports, dict) and saved_ports:
            merged["scoring"]["port_scores"] = saved_ports          # a deleted port must stay deleted
        cleaned, errors = clean(merged)
        if errors:
            cleaned = copy.deepcopy(DEFAULTS)
        _cache["cfg"], _cache["mtime"] = cleaned, mtime
        return copy.deepcopy(cleaned)


def get(path, default=None):
    cur = get_all()
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def save(new_config, merge=True):
    """Validate and save. Raises ConfigError with a list of readable problems."""
    with _lock:
        base = get_all() if merge else copy.deepcopy(DEFAULTS)
        merged = deep_merge(base, new_config)
        sc = (new_config or {}).get("scoring", {})
        if isinstance(sc, dict) and isinstance(sc.get("port_scores"), dict):
            merged["scoring"]["port_scores"] = copy.deepcopy(sc["port_scores"])     # replace, so deleted ports stay deleted
        cleaned, errors = clean(merged)
        if errors:
            raise ConfigError(errors)
        os.makedirs(os.path.dirname(CONFIG_FILE) or ".", exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cleaned, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
        _cache["cfg"] = None
        return get_all()


def reset():
    with _lock:
        try:
            os.remove(CONFIG_FILE)
        except OSError:
            pass
        _cache["cfg"] = None
        return get_all()


def apply_preset(name):
    if name not in PRESETS:
        raise ConfigError([f"unknown preset '{name}'"])
    keep = {"interfaces": get_all()["interfaces"]}           # a preset never changes the connections
    return save(deep_merge(deep_merge(DEFAULTS, PRESETS[name]["patch"]), keep), merge=False)


def preset_list():
    return [{"name": k, "title": v["title"], "about": v["about"]} for k, v in PRESETS.items()]


def snapshot(path, extra=None):
    """Save the settings used by a run, so results can be reproduced."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"saved_at": time.time(), "run": extra or {}, "config": get_all()}, f, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------- helpers for the engines
def algorithm_label(kex, cipher):
    if kex == "HYBRID_1024":
        return f"X25519+ML-KEM-1024 / {cipher}"
    if kex == "HYBRID_768":
        return f"X25519+ML-KEM-768 / {cipher}"
    return f"X25519 / {cipher}"


POLICY_NAMES = {"HIGH": "High Security Policy", "MEDIUM": "Standard Security Policy", "LOW": "Default Security Policy"}


def decision_matrix(cfg=None):
    """{(sensitivity, resource): {algorithm, policy, kex, symmetric_cipher}} from the settings."""
    cfg = cfg or get_all()
    out = {}
    for s in SENS:
        for r in RES:
            cell = cfg["policy"]["matrix"][s][r]
            out[(s, r)] = {"algorithm": algorithm_label(cell["kex"], cell["cipher"]), "policy": POLICY_NAMES[s],
                           "kex": cell["kex"], "symmetric_cipher": cell["cipher"]}
    return out
