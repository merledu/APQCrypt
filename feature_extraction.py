import pandas as pd
import time
import os
from status_manager import StatusManager
import debuglog

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, Padding
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    rdpcap = None

# How many payload bytes we keep per packet (as hex) for "peeking" (DPI).
# WHY 512 and not 128: a TLS ClientHello puts the website name (SNI)
# roughly 150-300 bytes into the packet, so 128 bytes is too short.
PAYLOAD_BYTES_SAVED = 512


def make_flow_id(src, sport, dst, dport, proto_class):
    """Same ID for both directions of one conversation."""
    a = (str(src), int(sport))
    b = (str(dst), int(dport))
    lo, hi = sorted([a, b])
    return f"{proto_class}|{lo[0]}:{lo[1]}|{hi[0]}:{hi[1]}"


def get_payload(pkt):
    """
    Application bytes of a packet (what the program inside is really sending).
    IMPORTANT: scapy turns DNS, NTP etc. into their own layers, so looking only
    for the 'Raw' layer MISSES them. We take everything after the TCP/UDP/ICMP
    header instead, and remove Ethernet padding.
    """
    for layer in (TCP, UDP, ICMP):
        if layer in pkt:
            data = bytes(pkt[layer].payload)
            if Padding in pkt:
                pad = len(bytes(pkt[Padding].load))
                if pad:
                    data = data[:len(data) - pad]
            return data
    return bytes(pkt[Raw].load) if Raw in pkt else b""


class FeatureExtractor:
    def __init__(self):
        self.output_file = "data/features.csv"
        self.start_time = None

    def extract_features(self, pcap_file):
        """Extract per-packet features from the captured file."""
        try:
            if not os.path.exists(pcap_file):
                StatusManager.update_status("Features", f"Error: PCAP file not found: {pcap_file}")
                return None
            file_size = os.path.getsize(pcap_file)
            if file_size == 0:
                StatusManager.update_status("Features", "Error: PCAP file is empty")
                return None

            self.start_time = time.time()
            debuglog.log("features", "stage_start", input=pcap_file, size_bytes=file_size, params={"payload_bytes_saved": PAYLOAD_BYTES_SAVED})
            StatusManager.update_status("Features", f"Extracting features from {pcap_file} ({file_size} bytes)...", 55)

            if rdpcap is None:
                StatusManager.update_status("Features", "Error: Scapy not available")
                return None

            packets = rdpcap(pcap_file)
            if not packets or len(packets) == 0:
                StatusManager.update_status("Features", "Error: No packets found in PCAP file")
                return None

            data = []
            failed_count = 0

            for idx, pkt in enumerate(packets):
                try:
                    # Every row ALWAYS gets Pkt_Index = position in the pcap, so
                    # later stages can match rows to packets even if some fail.
                    row = {"Pkt_Index": idx, "Timestamp": float(pkt.time)}

                    # ---------- ARP ----------
                    if ARP in pkt:
                        row.update({
                            "Source_IP": pkt[ARP].psrc, "Destination_IP": pkt[ARP].pdst,
                            "Source_Port": 0, "Dest_Port": 0, "Protocol": "ARP",
                            "Packet_Length": len(pkt), "TTL": 0, "IP_Flags": "",
                            "TCP_Flags": "", "Window": 0, "Payload_Len": 0, "First_Bytes_Hex": "",
                        })
                        row["Flow_ID"] = make_flow_id(row["Source_IP"], 0, row["Destination_IP"], 0, "ARP")
                        data.append(row)
                        continue

                    # ---------- IP layer (IPv4 or IPv6) ----------
                    if IP in pkt:
                        row["Source_IP"] = pkt[IP].src
                        row["Destination_IP"] = pkt[IP].dst
                        row["TTL"] = pkt[IP].ttl
                        row["IP_Flags"] = str(pkt[IP].flags)
                    elif IPv6 in pkt:
                        row["Source_IP"] = pkt[IPv6].src
                        row["Destination_IP"] = pkt[IPv6].dst
                        row["TTL"] = pkt[IPv6].hlim
                        row["IP_Flags"] = ""
                    else:
                        row["Source_IP"] = "NA"
                        row["Destination_IP"] = "NA"
                        row["TTL"] = 0
                        row["IP_Flags"] = ""

                    row["TCP_Flags"] = ""
                    row["Window"] = 0
                    proto_class = "OTHER"

                    if ICMP in pkt:
                        row["Protocol"] = "ICMP"
                        row["Source_Port"] = 0
                        row["Dest_Port"] = 0
                        proto_class = "ICMP"

                    elif TCP in pkt:
                        sport, dport = pkt[TCP].sport, pkt[TCP].dport
                        row["Source_Port"], row["Dest_Port"] = sport, dport
                        row["TCP_Flags"] = str(pkt[TCP].flags)   # REAL TCP flags, e.g. "S", "SA", "PA"
                        row["Window"] = pkt[TCP].window
                        proto_class = "TCP"
                        ports = {sport, dport}
                        if ports & {443, 8443}:
                            row["Protocol"] = "HTTPS"
                        elif ports & {80, 8000}:
                            row["Protocol"] = "HTTP"
                        elif 22 in ports:
                            row["Protocol"] = "SSH"
                        else:
                            row["Protocol"] = "TCP"

                    elif UDP in pkt:
                        sport, dport = pkt[UDP].sport, pkt[UDP].dport
                        row["Source_Port"], row["Dest_Port"] = sport, dport
                        proto_class = "UDP"
                        ports = {sport, dport}
                        if 53 in ports:
                            row["Protocol"] = "DNS"
                        elif 123 in ports:
                            row["Protocol"] = "NTP"
                        else:
                            row["Protocol"] = "UDP"
                    else:
                        row["Protocol"] = "OTHER"
                        row["Source_Port"] = 0
                        row["Dest_Port"] = 0

                    row["Packet_Length"] = len(pkt)

                    # ---------- Payload (what the application is really sending) ----------
                    payload = get_payload(pkt)
                    row["Payload_Len"] = len(payload)
                    row["First_Bytes_Hex"] = payload[:PAYLOAD_BYTES_SAVED].hex()

                    row["Flow_ID"] = make_flow_id(row["Source_IP"], row["Source_Port"],
                                                  row["Destination_IP"], row["Dest_Port"], proto_class)
                    data.append(row)

                except Exception as e:
                    failed_count += 1
                    print(f"[DEBUG] Packet {idx} parse error: {e}")
                    continue

            if not data:
                StatusManager.update_status("Features", f"Error: No packets extracted (failed: {failed_count}/{len(packets)})")
                return None

            df = pd.DataFrame(data)
            column_order = ["Pkt_Index", "Timestamp", "Flow_ID", "Source_IP", "Destination_IP",
                            "Source_Port", "Dest_Port", "Protocol", "Packet_Length", "TTL",
                            "IP_Flags", "TCP_Flags", "Window", "Payload_Len", "First_Bytes_Hex"]
            df = df[[c for c in column_order if c in df.columns]]

            # Write safely: temp file first, then rename (no half-written CSV)
            tmp = self.output_file + ".tmp"
            df.to_csv(tmp, index=False)
            os.replace(tmp, self.output_file)

            execution_time = time.time() - self.start_time
            StatusManager.record_module_timing("Feature Extraction", execution_time)
            debuglog.log("features", "stage_end", rows_in=int(len(packets)), rows_out=int(len(df)), seconds=round(execution_time, 3),
                         output=self.output_file, flows=int(df["Flow_ID"].nunique()), with_payload=int((df["Payload_Len"] > 0).sum()),
                         skipped=failed_count, result={k: int(v) for k, v in df["Protocol"].value_counts().items()})

            protocol_counts = df["Protocol"].value_counts().to_dict()
            with_payload = int((df["Payload_Len"] > 0).sum())
            message = (f"✓ Extracted features: {len(df)} packets ({with_payload} with payload, "
                       f"{df['Flow_ID'].nunique()} flows) | Protocols: {protocol_counts} | File: {self.output_file}")
            print(f"[DEBUG] {message}")
            StatusManager.update_status("Features", message, 70)
            return self.output_file

        except Exception as e:
            import traceback
            print(f"[DEBUG] Feature extraction error:\n{traceback.format_exc()}")
            StatusManager.update_status("Features", f"Error: {str(e)}")
            return None
