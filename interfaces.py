"""
Wrapper interface: small adapter classes around the EXTERNAL things APQCrypt depends on.

  packet_source   : where packets come from      (Mininet + tshark, or a pcap file)
  risk_model      : the trained AI model file    (scikit-learn Random Forest pickle)
  crypto_provider : the ML-KEM implementation    (liboqs, or a clearly-marked simulated one for development)

The pipeline asks for an adapter by KIND (get("packet_source")) and never calls the
external library directly. Which adapter is active is a setting (Settings / Interfaces page),
so an external part can be swapped without changing pipeline code.
"""
import os
import subprocess
import time
from abc import ABC, abstractmethod

import config as cfgmod


class Adapter(ABC):
    kind = ""
    name = ""
    title = ""
    about = ""

    @abstractmethod
    def check(self):
        """Return {"available": bool, "detail": str, "ms": float|None}. Never raises."""

    def info(self):
        return {"kind": self.kind, "name": self.name, "title": self.title, "about": self.about}


def _run_ok(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout).returncode == 0
    except Exception:
        return False


# ------------------------------------------------------------------ packet sources
class PacketSource(Adapter):
    kind = "packet_source"

    @abstractmethod
    def get_capture(self, count=1000):
        """Return the path of a capture file, or None."""


class MininetTsharkSource(PacketSource):
    name = "mininet"
    title = "Mininet + tshark (live test network)"
    about = "Builds a virtual network, generates traffic, and records it with tshark. Linux only."

    def check(self):
        t0 = time.perf_counter()
        sudo, mn, ts = _run_ok(["sudo", "-n", "true"]), _run_ok(["which", "mn"]), _run_ok(["which", "tshark"])
        missing = [n for n, ok in (("passwordless sudo", sudo), ("mininet (mn)", mn), ("tshark", ts)) if not ok]
        return {"available": not missing, "ms": round((time.perf_counter() - t0) * 1000, 1),
                "detail": "sudo, mininet and tshark found" if not missing else "missing: " + ", ".join(missing)}

    def get_capture(self, count=1000):
        from packet_capture import PacketCapture
        return PacketCapture().capture_packets(count)


class PcapFileSource(PacketSource):
    name = "pcap_file"
    title = "Capture file (.pcap / .pcapng)"
    about = "Reads an existing recording. Works on any computer, no Mininet needed."

    def __init__(self, path=None):
        self.path = path or cfgmod.get("interfaces.pcap_path", "data/traffic.pcapng")

    def check(self):
        t0 = time.perf_counter()
        try:
            if not os.path.isfile(self.path) or os.path.getsize(self.path) == 0:
                return {"available": False, "ms": None, "detail": f"file not found or empty: {self.path}"}
            with open(self.path, "rb") as f:
                magic = f.read(4)
            ok = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
            return {"available": ok, "ms": round((time.perf_counter() - t0) * 1000, 1),
                    "detail": f"{self.path} ({os.path.getsize(self.path)} bytes)" if ok else "not a pcap/pcapng file"}
        except OSError as e:
            return {"available": False, "ms": None, "detail": str(e)}

    def get_capture(self, count=1000):
        return self.path if self.check()["available"] else None


# ------------------------------------------------------------------ risk model
class RiskModelProvider(Adapter):
    kind = "risk_model"


class RandomForestFile(RiskModelProvider):
    name = "random_forest"
    title = "Random Forest model file (scikit-learn pickle)"
    about = "The behaviour-risk model trained on CIC-IDS2017."

    def check(self):
        t0 = time.perf_counter()
        try:
            import sensitivity_engine as se
            m = se.get_cached_model(se.MODEL_PATH)
            est = getattr(m.model, "n_estimators", "?")
            return {"available": True, "ms": round((time.perf_counter() - t0) * 1000, 1),
                    "detail": f"{os.path.basename(se.MODEL_PATH)} loaded: {est} trees, {len(m.features)} features, classes {[str(c) for c in m.classes]}"}
        except Exception as e:
            return {"available": False, "ms": None, "detail": f"cannot load model: {str(e)[:160]}"}


# ------------------------------------------------------------------ crypto providers
class CryptoProvider(Adapter):
    kind = "crypto_provider"
    quantum_safe = False
    KEM_NAMES = {"HYBRID_1024": ["ML-KEM-1024", "Kyber1024"], "HYBRID_768": ["ML-KEM-768", "Kyber768"]}

    @abstractmethod
    def kem_secret(self, kex):
        """Return (shared_secret_bytes, kem_label)."""


class LiboqsProvider(CryptoProvider):
    name = "liboqs"
    title = "liboqs (real ML-KEM)"
    about = "The Open Quantum Safe library. Real quantum-safe key agreement (NIST FIPS 203)."
    quantum_safe = True

    def kem_secret(self, kex):
        try:
            import oqs
        except Exception:
            raise RuntimeError("liboqs-python (oqs) not installed -- needed for ML-KEM")
        last = None
        for name in self.KEM_NAMES[kex]:
            try:
                with oqs.KeyEncapsulation(name) as kem:
                    pk = kem.generate_keypair()
                    ct, ss_sender = kem.encap_secret(pk)
                    ss_receiver = kem.decap_secret(ct)
                if ss_sender != ss_receiver:
                    raise RuntimeError("ML-KEM secrets do not match")
                return ss_sender, name
            except Exception as e:
                last = e
        raise RuntimeError(f"ML-KEM not available in this liboqs build: {last}")

    def check(self):
        t0 = time.perf_counter()
        try:
            _, name = self.kem_secret("HYBRID_1024")
            return {"available": True, "ms": round((time.perf_counter() - t0) * 1000, 2),
                    "detail": f"{name} key agreement round trip works"}
        except Exception as e:
            return {"available": False, "ms": None, "detail": str(e)[:200]}


class SimulatedKemProvider(CryptoProvider):
    name = "simulated"
    title = "Simulated KEM (DEVELOPMENT ONLY, not quantum-safe)"
    about = "Random bytes instead of ML-KEM so the dashboard can be tested without liboqs. Results are labelled DEV-SIM-KEM and are NOT counted as quantum-safe."
    quantum_safe = False

    def kem_secret(self, kex):
        return os.urandom(32), "DEV-SIM-KEM"

    def check(self):
        return {"available": True, "ms": 0.0, "detail": "always available. NOT quantum-safe. Do not use for results."}


# ------------------------------------------------------------------ registry
REGISTRY = {
    "packet_source": {"mininet": MininetTsharkSource, "pcap_file": PcapFileSource},
    "risk_model": {"random_forest": RandomForestFile},
    "crypto_provider": {"liboqs": LiboqsProvider, "simulated": SimulatedKemProvider},
}
ACTIVE_KEY = {"packet_source": "packet_source", "crypto_provider": "crypto_provider"}


def active_name(kind):
    if kind in ACTIVE_KEY:
        return cfgmod.get(f"interfaces.{ACTIVE_KEY[kind]}")
    return next(iter(REGISTRY[kind]))


def get(kind):
    return REGISTRY[kind][active_name(kind)]()


def health():
    rows = []
    for kind, impls in REGISTRY.items():
        active = active_name(kind)
        for name, cls in impls.items():
            a = cls()
            try:
                res = a.check()
            except Exception as e:                         # a check must never break the page
                res = {"available": False, "ms": None, "detail": str(e)[:200]}
            rows.append({**a.info(), "active": name == active, "quantum_safe": getattr(a, "quantum_safe", None), **res})
    return rows


def test(kind, name):
    cls = REGISTRY.get(kind, {}).get(name)
    if not cls:
        return None
    a = cls()
    try:
        res = a.check()
    except Exception as e:
        res = {"available": False, "ms": None, "detail": str(e)[:200]}
    return {**a.info(), **res}
