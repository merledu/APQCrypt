import os
import time
import json
import pandas as pd

from status_manager import StatusManager

try:
    import oqs
except ImportError:
    oqs = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

try:
    from scapy.all import rdpcap
    from feature_extraction import get_payload
except ImportError:
    rdpcap = None

try:
    import psutil
except ImportError:
    psutil = None

KEY_LEN = {"AES-256-GCM": 32, "AES-128-GCM": 16, "ChaCha20-Poly1305": 32}
SELF_CHECK_PACKETS = 20      # how many packets get the decrypt + tamper test
MAX_FLOW_EVENTS = 300        # per-conversation debug events kept per run

import debuglog


def _pq_secret(kex):
    """ML-KEM key agreement through the active crypto provider (wrapper interface: interfaces.py).
    Both sides are simulated in this one program."""
    import interfaces
    return interfaces.get("crypto_provider").kem_secret(kex)


def establish_session(kex, cipher_name, flow_id):
    """
    Key agreement for ONE conversation, then HKDF (RFC 5869) to make the real key.
      X25519      : normal (classical) key exchange
      HYBRID_xxx  : X25519 secret + ML-KEM secret joined, then HKDF  (hybrid)
    Returns (key, handshake_ms, label)
    """
    t0 = time.perf_counter()
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    ss_classic = a.exchange(b.public_key())
    if ss_classic != b.exchange(a.public_key()):
        raise RuntimeError("X25519 secrets do not match")

    ikm, label = ss_classic, "X25519"
    if kex.startswith("HYBRID"):
        ss_pq, kem_name = _pq_secret(kex)
        ikm = ss_classic + ss_pq
        label = f"X25519+{kem_name}"

    info = f"APQCrypt-v1|{flow_id}|{cipher_name}".encode()
    key = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN[cipher_name], salt=None, info=info).derive(ikm)
    return key, (time.perf_counter() - t0) * 1000, label


class FlowSession:
    __slots__ = ("aead", "cipher_name", "key", "handshake_ms", "label")

    def __init__(self, key, cipher_name, handshake_ms, label):
        self.key = key
        self.cipher_name = cipher_name
        self.handshake_ms = handshake_ms
        self.label = label
        self.aead = AESGCM(key) if cipher_name.startswith("AES") else ChaCha20Poly1305(key)


def encrypt_payload(session, plaintext, aad=b""):
    """AEAD encryption (also detects tampering). Returns (nonce+ciphertext+tag, microseconds)."""
    t0 = time.perf_counter_ns()
    nonce = os.urandom(12)
    ct = nonce + session.aead.encrypt(nonce, plaintext, aad)
    return ct, (time.perf_counter_ns() - t0) / 1000


def decrypt_payload(session, blob, aad=b""):
    return session.aead.decrypt(blob[:12], blob[12:], aad)


def get_flow_id(rec):
    if rec.get("Flow_ID") and str(rec.get("Flow_ID")) != "NA":
        return str(rec["Flow_ID"])
    a = (str(rec.get("Source_IP", "")), int(rec.get("Source_Port", 0) or 0))
    b = (str(rec.get("Destination_IP", "")), int(rec.get("Dest_Port", 0) or 0))
    return str(tuple(sorted([a, b])))


class EncryptionEngine:
    def __init__(self, output_file="data/encrypted_results.csv"):
        self.output_file = output_file
        self.checks_file = "data/encryption_checks.json"      # None = do not write (used by the comparison worker)
        self.start_time = None
        self.last_stats = {}

    def encrypt_traffic(self, policy_file, pcap_file):
        try:
            if not os.path.exists(policy_file):
                StatusManager.update_status("Encryption", f"Error: Policy file not found: {policy_file}")
                return None
            if not os.path.exists(pcap_file):
                StatusManager.update_status("Encryption", f"Error: PCAP file not found: {pcap_file}")
                return None
            if rdpcap is None:
                StatusManager.update_status("Encryption", "Error: Scapy not available")
                return None
            if not CRYPTO_OK:
                StatusManager.update_status("Encryption", "Error: cryptography library not available")
                return None

            self.start_time = time.time()
            import interfaces
            debuglog.log("encryption", "stage_start", input=policy_file, pcap=pcap_file,
                         params={"crypto_provider": interfaces.active_name("crypto_provider"), "self_check_packets": SELF_CHECK_PACKETS})
            StatusManager.update_status("Encryption", "Loading policy decisions and packet payloads...", 99)

            df = pd.read_csv(policy_file)
            if len(df) == 0:
                StatusManager.update_status("Encryption", "Error: Policy file is empty")
                return None
            packets = rdpcap(pcap_file)
            records = df.to_dict("records")
            n = len(records)
            # Timing starts HERE, after the file is loaded, so the numbers measure
            # key exchange + encryption only (reading the pcap is the same for every mode).
            wall0, cpu0 = time.perf_counter(), time.process_time()

            sessions = {}
            ct_len, enc_us, hs_ms, new_hs, flow_ids, kex_used, pay_len = ([None] * n for _ in range(7))
            new_hs = [False] * n
            flow_first = {}                      # flow -> (sensitivity, label)
            checks = {"roundtrip_ok": 0, "roundtrip_fail": 0, "tamper_detected": 0, "tamper_missed": 0}
            checked = 0

            for i, rec in enumerate(records):
                pkt_idx = int(rec["Pkt_Index"]) if rec.get("Pkt_Index") is not None and pd.notna(rec.get("Pkt_Index")) else i
                pkt = packets[pkt_idx] if 0 <= pkt_idx < len(packets) else None   # match by packet number

                flow_id = get_flow_id(rec)
                flow_ids[i] = flow_id
                cipher_name = str(rec.get("Symmetric_Cipher", "AES-256-GCM"))
                kex = str(rec.get("Key_Exchange", "")) or ("HYBRID_1024" if rec.get("PQC_Handshake_Used") else "X25519")
                if kex not in ("X25519", "HYBRID_768", "HYBRID_1024"):
                    kex = "HYBRID_1024" if rec.get("PQC_Handshake_Used") else "X25519"

                if flow_id not in sessions:
                    key, hms, label = establish_session(kex, cipher_name, flow_id)
                    sessions[flow_id] = FlowSession(key, cipher_name, hms, label)
                    hs_ms[i] = round(hms, 4)
                    new_hs[i] = True
                    flow_first[flow_id] = (str(rec.get("Sensitivity", "")), label)
                    if len(sessions) <= MAX_FLOW_EVENTS:
                        debuglog.log("encryption", "key exchange", flow=flow_id, sensitivity=str(rec.get("Sensitivity", "")),
                                     key_exchange=label, cipher=cipher_name, handshake_ms=round(hms, 3))
                session = sessions[flow_id]
                kex_used[i] = session.label

                payload = get_payload(pkt) if pkt is not None else b""
                pay_len[i] = len(payload)
                if not payload:
                    ct_len[i], enc_us[i] = 0, 0.0
                    continue

                aad = flow_id.encode()
                ct, us = encrypt_payload(session, payload, aad)
                ct_len[i], enc_us[i] = len(ct), round(us, 2)

                # ---- self-checks on a small sample: decrypt must match, tampering must be caught ----
                if checked < SELF_CHECK_PACKETS:
                    checked += 1
                    try:
                        checks["roundtrip_ok" if decrypt_payload(session, ct, aad) == payload else "roundtrip_fail"] += 1
                    except Exception:
                        checks["roundtrip_fail"] += 1
                    bad = ct[:-1] + bytes([ct[-1] ^ 0x01])
                    try:
                        decrypt_payload(session, bad, aad)
                        checks["tamper_missed"] += 1
                    except InvalidTag:
                        checks["tamper_detected"] += 1

                if i % 200 == 0:
                    StatusManager.update_status("Encryption", f"Encrypting... {i}/{n} packets ({len(sessions)} flows)", 99)

            out = df.copy()
            out["Flow_Key"] = flow_ids
            out["New_Flow_Handshake"] = new_hs
            out["Handshake_Time_ms"] = hs_ms
            out["Key_Exchange_Used"] = kex_used
            out["Payload_Length"] = pay_len
            out["Ciphertext_Length"] = ct_len
            out["Encrypt_Time_us"] = enc_us

            tmp = self.output_file + ".tmp"
            out.to_csv(tmp, index=False)
            os.replace(tmp, self.output_file)

            high_flows = [f for f, (s, _l) in flow_first.items() if s == "HIGH"]
            high_pq = [f for f in high_flows if "ML-KEM" in flow_first[f][1] or "Kyber" in flow_first[f][1]]
            pq_flows = [f for f, (_s, l) in flow_first.items() if "ML-KEM" in l or "Kyber" in l]
            total_hs = sum(h for h in hs_ms if h)
            total_enc_us = sum(e for e in enc_us if e)
            payload_total = sum(p for p in pay_len if p)
            ct_total = sum(c for c in ct_len if c)
            self.last_stats = {
                "wall_s": round(time.perf_counter() - wall0, 4),
                "cpu_s": round(time.process_time() - cpu0, 4),
                "mem_mb": round(psutil.Process().memory_info().rss / 1e6, 1) if psutil else None,
                "packets": n, "flows": len(sessions),
                "pq_flows": len(pq_flows),
                "pq_flow_share": round(len(pq_flows) / max(1, len(sessions)), 3),
                "high_flows": len(high_flows), "high_flows_pq": len(high_pq),
                "high_pq_coverage": round(len(high_pq) / len(high_flows), 3) if high_flows else None,
                "handshake_ms_total": round(total_hs, 3),
                "encrypt_ms_total": round(total_enc_us / 1000, 3),
                "overhead_bytes": int(ct_total - payload_total),
                "checks": checks,
            }
            if self.checks_file:
                try:
                    with open(self.checks_file, "w") as f:
                        json.dump({"checks": checks, **{k: v for k, v in self.last_stats.items() if k != "checks"}}, f, indent=2)
                except Exception:
                    pass

            secs = time.time() - self.start_time
            StatusManager.record_module_timing("Encryption Engine", secs)
            debuglog.log("encryption", "stage_end", rows_in=n, rows_out=n, seconds=round(secs, 3), output=self.output_file,
                         flows=len(sessions), quantum_safe_flows=len(pq_flows), high_flows=len(high_flows), high_flows_quantum_safe=len(high_pq),
                         handshake_ms_total=round(total_hs, 3), encrypt_ms_total=round(total_enc_us / 1000, 3), checks=checks,
                         level_note="tamper_missed must be 0" if checks["tamper_missed"] == 0 else "TAMPERING NOT DETECTED")
            msg = (f"✓ Encryption Complete | {n} packets | {len(sessions)} flows | {len(pq_flows)} quantum-safe (hybrid) flows | "
                   f"Handshake total: {round(total_hs, 2)}ms | Encrypt total: {round(total_enc_us / 1000, 2)}ms | "
                   f"Decrypt checks OK: {checks['roundtrip_ok']} | Tamper caught: {checks['tamper_detected']}/"
                   f"{checks['tamper_detected'] + checks['tamper_missed']} | File: {self.output_file}")
            print(f"[DEBUG] {msg}")
            StatusManager.update_status("Encryption", msg, 100)
            return self.output_file

        except Exception as e:
            import traceback
            print(f"[DEBUG] Encryption engine error:\n{traceback.format_exc()}")
            StatusManager.update_status("Encryption", f"Error: {str(e)}")
            debuglog.log("encryption", "encryption error", "error", error=str(e)[:200])
            return None
