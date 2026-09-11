import os
import time
import pandas as pd

from status_manager import StatusManager

try:
    import oqs
except ImportError:
    oqs = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    Cipher = None

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    rdpcap = None


ML_KEM_NAME = "ML-KEM-1024"  # matches the "ML-KEM-1024" leg of Selected_Algorithm


def get_flow_key(row):
    """
    Direction-independent flow identifier: two packets going opposite
    ways in the same conversation (client->server, server->client)
    must map to the SAME key, so they share one handshake/session key
    -- exactly like a real TCP/TLS connection.
    """
    a = (str(row.get("Source_IP", "")), int(row.get("Source_Port", 0) or 0))
    b = (str(row.get("Destination_IP", "")), int(row.get("Dest_Port", 0) or 0))
    endpoints = tuple(sorted([a, b]))
    protocol = str(row.get("Protocol", ""))
    # ARP/ICMP have no ports -- keep them distinct from TCP/UDP flows
    # between the same two hosts.
    proto_class = "L2" if protocol in ("ARP",) else ("ICMP" if protocol == "ICMP" else "L4")
    return (endpoints, proto_class)


class FlowSession:
    """
    Holds the derived symmetric key for one flow, generated exactly
    once (on the first packet of that flow) and reused for every
    other packet in the same flow -- avoids repeating an expensive
    PQC handshake per packet.
    """
    __slots__ = ("key", "cipher_name", "handshake_ms", "did_pqc")

    def __init__(self, key, cipher_name, handshake_ms, did_pqc):
        self.key = key
        self.cipher_name = cipher_name
        self.handshake_ms = handshake_ms
        self.did_pqc = did_pqc


def establish_session(cipher_name, use_pqc):
    """
    Runs the actual key-establishment step for a new flow:
      - If use_pqc: a REAL ML-KEM-1024 handshake (keygen + encapsulate
        + decapsulate) via liboqs. The resulting 32-byte shared secret
        becomes the AES-256-GCM key -- this is the hybrid scheme:
        PQC does key agreement, AES does bulk encryption.
      - Otherwise: a random symmetric key sized for the chosen cipher.
    Returns (key_bytes, handshake_time_ms).
    """
    t0 = time.time()

    if use_pqc:
        if oqs is None:
            raise RuntimeError("oqs (liboqs-python) not installed -- required for ML-KEM handshake")
        with oqs.KeyEncapsulation(ML_KEM_NAME) as kem:
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_sender = kem.encap_secret(public_key)
            shared_secret_receiver = kem.decap_secret(ciphertext)
        # In a real deployment these would be verified equal on the
        # receiving side before use; enforced here for correctness.
        assert shared_secret_sender == shared_secret_receiver
        key = shared_secret_sender  # 32 bytes -> exactly an AES-256 key
    else:
        key_len = {"AES-128-CBC": 16, "AES-256-CBC": 32, "ChaCha20": 32}.get(cipher_name, 32)
        key = os.urandom(key_len)

    handshake_ms = (time.time() - t0) * 1000
    return key, handshake_ms


def encrypt_payload(cipher_name, key, plaintext):
    """
    Encrypts one packet's payload with the real algorithm for its
    flow's session key. Returns (ciphertext_bytes, encrypt_time_us).
    """
    t0 = time.time()

    if cipher_name in ("AES-256-GCM",):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # unique per packet -- this is what keeps
        ciphertext = nonce + aesgcm.encrypt(nonce, plaintext, None)  # key reuse safe

    elif cipher_name in ("AES-128-CBC", "AES-256-CBC"):
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = iv + encryptor.update(padded) + encryptor.finalize()

    elif cipher_name == "ChaCha20":
        # cryptography's ChaCha20 needs a 16-byte nonce: 4-byte counter
        # (starts at 0) + 12-byte random nonce, per RFC 7539.
        nonce = (0).to_bytes(4, "little") + os.urandom(12)
        encryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
        ciphertext = nonce[4:] + encryptor.update(plaintext) + encryptor.finalize()

    else:
        raise ValueError(f"Unknown cipher: {cipher_name}")

    encrypt_us = (time.time() - t0) * 1_000_000
    return ciphertext, encrypt_us


def decrypt_payload(cipher_name, key, ciphertext):
    """
    Reverses encrypt_payload() exactly -- given the same key and the
    ciphertext it produced, returns the original plaintext. This is
    the actual proof that encryption worked: if this doesn't return
    byte-for-byte the same plaintext that went in, something is wrong.
    """
    if cipher_name in ("AES-256-GCM",):
        nonce, actual_ct = ciphertext[:12], ciphertext[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, actual_ct, None)

    elif cipher_name in ("AES-128-CBC", "AES-256-CBC"):
        iv, actual_ct = ciphertext[:16], ciphertext[16:]
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(actual_ct) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

    elif cipher_name == "ChaCha20":
        nonce12, actual_ct = ciphertext[:12], ciphertext[12:]
        nonce = (0).to_bytes(4, "little") + nonce12
        decryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
        plaintext = decryptor.update(actual_ct) + decryptor.finalize()

    else:
        raise ValueError(f"Unknown cipher: {cipher_name}")

    return plaintext


class EncryptionEngine:
    def __init__(self):
        self.output_file = "data/encrypted_results.csv"
        self.start_time = None

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
            if Cipher is None:
                StatusManager.update_status("Encryption", "Error: cryptography library not available")
                return None

            self.start_time = time.time()
            StatusManager.update_status("Encryption", "Loading policy decisions and packet payloads...", 99)

            df = pd.read_csv(policy_file)
            if len(df) == 0:
                StatusManager.update_status("Encryption", "Error: Policy file is empty")
                return None

            packets = rdpcap(pcap_file)
            if len(packets) != len(df):
                # Not fatal -- align on the shorter length and proceed,
                # but this indicates the pcap and policy.csv are out of
                # sync (e.g. from different runs).
                StatusManager.update_status(
                    "Encryption",
                    f"Warning: packet count ({len(packets)}) != policy rows ({len(df)}), aligning to shorter"
                )

            n = min(len(packets), len(df))

            StatusManager.update_status(
                "Encryption",
                f"Encrypting {n} packets (real ML-KEM + AES/ChaCha20, per-flow session keys)...",
                99
            )

            sessions = {}          # flow_key -> FlowSession
            ciphertext_lengths = [None] * n
            encrypt_times_us = [None] * n
            handshake_times_ms = [None] * n
            new_handshake_flags = [False] * n
            flow_keys_out = [None] * n

            pqc_handshakes_done = 0
            plain_handshakes_done = 0

            for i in range(n):
                row = df.iloc[i]
                pkt = packets[i]

                flow_key = get_flow_key(row)
                flow_keys_out[i] = str(flow_key)

                cipher_name = str(row.get("Symmetric_Cipher", "AES-128-CBC"))

                if flow_key not in sessions:
                    pqc_flag = bool(row.get("PQC_Handshake_Used", False))
                    key, handshake_ms = establish_session(cipher_name, pqc_flag)
                    sessions[flow_key] = FlowSession(key, cipher_name, handshake_ms, pqc_flag)
                    handshake_times_ms[i] = round(handshake_ms, 4)
                    new_handshake_flags[i] = True
                    if pqc_flag:
                        pqc_handshakes_done += 1
                    else:
                        plain_handshakes_done += 1

                session = sessions[flow_key]

                # Extract real payload bytes from the actual captured packet.
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                else:
                    payload = b""

                if len(payload) == 0:
                    # Nothing to encrypt (e.g. bare ARP/ICMP with no
                    # payload) -- record zero-cost, no crypto call needed.
                    ciphertext_lengths[i] = 0
                    encrypt_times_us[i] = 0.0
                    continue

                ciphertext, encrypt_us = encrypt_payload(session.cipher_name, session.key, payload)
                ciphertext_lengths[i] = len(ciphertext)
                encrypt_times_us[i] = round(encrypt_us, 2)

                if i % 100 == 0:
                    StatusManager.update_status(
                        "Encryption",
                        f"Encrypting... {i}/{n} packets ({len(sessions)} flows, "
                        f"{pqc_handshakes_done} PQC handshakes so far)",
                        99
                    )

            out = df.iloc[:n].copy()
            out["Flow_Key"] = flow_keys_out
            out["New_Flow_Handshake"] = new_handshake_flags
            out["Handshake_Time_ms"] = handshake_times_ms
            out["Ciphertext_Length"] = ciphertext_lengths
            out["Encrypt_Time_us"] = encrypt_times_us

            out.to_csv(self.output_file, index=False)

            total_time = time.time() - self.start_time
            StatusManager.record_module_timing("Encryption Engine", total_time)

            total_pqc_handshake_ms = sum(h for h in handshake_times_ms if h is not None and h > 0)
            total_encrypt_us = sum(e for e in encrypt_times_us if e is not None)

            message = (
                f"✓ Encryption Complete | {n} packets | {len(sessions)} flows | "
                f"{pqc_handshakes_done} real ML-KEM handshakes, {plain_handshakes_done} symmetric-only | "
                f"Total handshake time: {round(total_pqc_handshake_ms, 2)}ms | "
                f"Total encrypt time: {round(total_encrypt_us/1000, 2)}ms | "
                f"File: {self.output_file}"
            )
            print(f"[DEBUG] {message}")
            StatusManager.update_status("Encryption", message, 100)
            return self.output_file

        except Exception as e:
            import traceback
            print(f"[DEBUG] Encryption engine error:\n{traceback.format_exc()}")
            StatusManager.update_status("Encryption", f"Error: {str(e)}")
            return None
