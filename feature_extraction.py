import pandas as pd
import time
import os
from status_manager import StatusManager

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    rdpcap = None


class FeatureExtractor:
    def __init__(self):
        self.output_file = "data/features.csv"
        self.start_time = None

    def extract_features(self, pcap_file):
        """Extract features from captured packets"""
        try:
            if not os.path.exists(pcap_file):
                StatusManager.update_status("Features", f"Error: PCAP file not found: {pcap_file}")
                return None

            file_size = os.path.getsize(pcap_file)
            if file_size == 0:
                StatusManager.update_status("Features", "Error: PCAP file is empty")
                return None

            self.start_time = time.time()
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
                    row = {}

                    # ---------- Layer 2: ARP ----------
                    if ARP in pkt:
                        row["Source_IP"] = pkt[ARP].psrc
                        row["Destination_IP"] = pkt[ARP].pdst
                        row["Source_Port"] = 0
                        row["Dest_Port"] = 0
                        row["Protocol"] = "ARP"
                        row["Packet_Length"] = len(pkt)
                        row["TTL"] = 0
                        row["Flags"] = ""
                        data.append(row)
                        continue

                    # ---------- Layer 3: IP-based packets ----------
                    if IP in pkt:
                        row["Source_IP"] = pkt[IP].src
                        row["Destination_IP"] = pkt[IP].dst
                        row["TTL"] = pkt[IP].ttl
                        row["Flags"] = str(pkt[IP].flags) if hasattr(pkt[IP], 'flags') else ""
                    else:
                        row["Source_IP"] = "NA"
                        row["Destination_IP"] = "NA"
                        row["TTL"] = 0
                        row["Flags"] = ""

                    # ---------- ICMP ----------
                    if ICMP in pkt:
                        row["Protocol"] = "ICMP"
                        row["Source_Port"] = 0
                        row["Dest_Port"] = 0

                    # ---------- TCP ----------
                    elif TCP in pkt:
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        row["Source_Port"] = sport
                        row["Dest_Port"] = dport

                        if dport == 443 or sport == 443 or dport == 8443 or sport == 8443:
                            row["Protocol"] = "HTTPS"
                        elif dport == 80 or sport == 80 or dport == 8000 or sport == 8000:
                            row["Protocol"] = "HTTP"
                        else:
                            row["Protocol"] = "TCP"

                    # ---------- UDP ----------
                    elif UDP in pkt:
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        row["Source_Port"] = sport
                        row["Dest_Port"] = dport

                        if dport == 53 or sport == 53:
                            row["Protocol"] = "DNS"
                        else:
                            row["Protocol"] = "UDP"

                    # ---------- Other / unrecognized ----------
                    else:
                        row["Protocol"] = "OTHER"
                        row["Source_Port"] = 0
                        row["Dest_Port"] = 0

                    # Packet metadata
                    row["Packet_Length"] = len(pkt)

                    data.append(row)

                except Exception as e:
                    failed_count += 1
                    print(f"[DEBUG] Packet {idx} parse error: {e}")
                    continue

            if not data:
                StatusManager.update_status("Features", f"Error: No packets extracted (failed: {failed_count}/{len(packets)})")
                return None

            # Create DataFrame
            df = pd.DataFrame(data)

            # Ensure proper column order
            column_order = ["Source_IP", "Destination_IP", "Source_Port", "Dest_Port",
                           "Protocol", "Packet_Length", "TTL", "Flags"]
            existing_cols = [c for c in column_order if c in df.columns]
            df = df[existing_cols]

            # Save to CSV
            df.to_csv(self.output_file, index=False)

            # Record timing
            execution_time = time.time() - self.start_time
            StatusManager.record_module_timing("Feature Extraction", execution_time)

            # Get statistics
            protocol_counts = df["Protocol"].value_counts().to_dict() if "Protocol" in df.columns else {}

            message = (
                f"✓ Extracted features: {len(df)} packets | "
                f"Protocols: {protocol_counts} | "
                f"File: {self.output_file}"
            )

            print(f"[DEBUG] {message}")
            StatusManager.update_status("Features", message, 70)
            return self.output_file

        except FileNotFoundError:
            StatusManager.update_status("Features", f"Error: PCAP file not found: {pcap_file}")
            return None
        except Exception as e:
            import traceback
            print(f"[DEBUG] Feature extraction error:\n{traceback.format_exc()}")
            StatusManager.update_status("Features", f"Error: {str(e)}")
            return None
