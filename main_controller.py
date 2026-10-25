from packet_capture import PacketCapture
from feature_extraction import FeatureExtractor
from sensitivity_engine import SensitivityEngine
from policy_engine import PolicyEngine
from encryption_engine import EncryptionEngine
from status_manager import StatusManager
import os
import time
import argparse


class PipelineController:
    def __init__(self):
        self.capture = PacketCapture()
        self.extractor = FeatureExtractor()
        self.engine = SensitivityEngine()
        self.policy = PolicyEngine()
        self.encryptor = EncryptionEngine()
        self.total_start = None

    def _fail(self, msg):
        print(f"[ERROR] {msg}")
        StatusManager.update_status("Error", msg)
        return False

    def run(self, mode="adaptive", replay_pcap=None, force_resource=None):
        """
        mode          : adaptive | static_aes | static_pqc
        replay_pcap   : path to an existing capture -> skips the slow capture step
                        (use this so every mode sees EXACTLY the same traffic)
        force_resource: AVAILABLE | CONSTRAINED -> simulate busy/free computer
        """
        self.total_start = time.time()
        try:
            StatusManager.clear_timings()
            print("\n" + "=" * 60 + f"\n   PIPELINE STARTED  (mode={mode})\n" + "=" * 60)

            if replay_pcap and os.path.exists(replay_pcap):
                pcap_file = replay_pcap
                print(f"[STAGE 1] Skipped capture, replaying {pcap_file}")
                StatusManager.update_status("Capture", f"Replaying existing capture: {pcap_file}", 50)
            else:
                print("\n[STAGE 1] Starting packet capture...")
                StatusManager.update_status("Capture", "Starting packet capture...", 5)
                t = time.time()
                pcap_file = self.capture.capture_packets(1000)
                StatusManager.record_module_timing("Packet Capture", time.time() - t)
                if not pcap_file:
                    return self._fail("Packet capture failed - aborting pipeline")

            if mode == "adaptive" and not force_resource:
                try:
                    from policy_engine import prefetch_resource_status
                    prefetch_resource_status()          # the CPU reading waits in the background
                except Exception:
                    pass
            print("\n[STAGE 2] Feature extraction...")
            feature_file = self.extractor.extract_features(pcap_file)
            if not feature_file:
                return self._fail("Feature extraction failed - aborting pipeline")

            print("\n[STAGE 3] Sensitivity analysis...")
            result_file = self.engine.classify_sensitivity(feature_file)
            if not result_file:
                return self._fail("Sensitivity analysis failed - aborting pipeline")

            print("\n[STAGE 4] Policy decision engine...")
            policy_file = self.policy.select_policies(result_file, mode=mode, force_resource=force_resource)
            if not policy_file:
                return self._fail("Policy engine failed - aborting pipeline")

            print("\n[STAGE 5] Encryption engine...")
            encrypted_file = self.encryptor.encrypt_traffic(policy_file, pcap_file)
            if not encrypted_file:
                return self._fail("Encryption engine failed - aborting pipeline")

            total_time = time.time() - self.total_start
            StatusManager.record_module_timing("Total Execution", total_time)
            msg = (f"✓ Pipeline Completed ({mode}) in {round(total_time, 2)} seconds | "
                   f"Outputs: {pcap_file}, {feature_file}, {result_file}, {policy_file}, {encrypted_file}")
            print(f"\n[SUCCESS] {msg}\n" + "=" * 60 + "\n")
            StatusManager.update_status("Finished", msg, 100)
            return True

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return self._fail(f"Pipeline error: {str(e)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="adaptive", choices=["adaptive", "static_aes", "static_pqc"])
    ap.add_argument("--replay", default=None, help="existing pcap to reuse, e.g. data/traffic.pcapng")
    ap.add_argument("--force-resource", default=None, choices=["AVAILABLE", "CONSTRAINED"])
    a = ap.parse_args()
    ok = PipelineController().run(mode=a.mode, replay_pcap=a.replay, force_resource=a.force_resource)
    exit(0 if ok else 1)
