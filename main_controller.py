from packet_capture import PacketCapture        # kept so the Mininet adapter (interfaces.py) can use it
from feature_extraction import FeatureExtractor
from sensitivity_engine import SensitivityEngine
from policy_engine import PolicyEngine
from encryption_engine import EncryptionEngine
from status_manager import StatusManager
import config as cfgmod
import debuglog
import interfaces
import os
import time
import argparse

STAGES = ["capture", "features", "sensitivity", "policy", "encryption"]
STAGE_FILES = {"capture": "data/traffic.pcapng", "features": "data/features.csv", "sensitivity": "data/results.csv",
               "policy": "data/policy.csv", "encryption": "data/encrypted_results.csv"}


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
        debuglog.log("pipeline", msg, "error")
        StatusManager.update_status("Error", msg)
        return False

    def run(self, mode="adaptive", replay_pcap=None, force_resource=None, stop_after=None, start_from=None):
        """
        mode          : adaptive | static_aes | static_pqc
        replay_pcap   : path to an existing capture -> skips the slow capture step
        force_resource: AVAILABLE | CONSTRAINED -> simulate a busy/free computer
        stop_after    : stop after this step (debugging: look at one step's output)
        start_from    : re-run from this step using the files already saved by earlier steps
        """
        self.total_start = time.time()
        start_idx = STAGES.index(start_from) if start_from in STAGES else 0
        stop_idx = STAGES.index(stop_after) if stop_after in STAGES else len(STAGES) - 1
        if stop_idx < start_idx:
            return self._fail("'stop after' step comes before the 'start from' step")
        try:
            StatusManager.clear_timings()
            if start_idx == 0:
                debuglog.clear()
            cfgmod.snapshot("data/run_config.json", {"mode": mode, "replay": bool(replay_pcap), "force_resource": force_resource,
                                                     "stop_after": stop_after, "start_from": start_from})
            debuglog.log("pipeline", "run_start", mode=mode, replay=replay_pcap, force_resource=force_resource,
                         stop_after=stop_after, start_from=start_from,
                         packet_source=interfaces.active_name("packet_source"), crypto_provider=interfaces.active_name("crypto_provider"))
            print("\n" + "=" * 60 + f"\n   PIPELINE STARTED  (mode={mode})\n" + "=" * 60)

            # ---------- STAGE 1: capture (through the packet-source adapter) ----------
            if start_idx == 0:
                source = interfaces.PcapFileSource(replay_pcap) if replay_pcap and os.path.exists(replay_pcap) else interfaces.get("packet_source")
                debuglog.log("capture", "stage_start", source=source.name, title=source.title)
                if source.name == "pcap_file":
                    pcap_file = source.get_capture()
                    if not pcap_file:
                        return self._fail("Capture file not found or not a valid pcap. Check Interfaces / Settings.")
                    print(f"[STAGE 1] Using capture file {pcap_file}")
                    StatusManager.update_status("Capture", f"Using existing capture: {pcap_file}", 50)
                    debuglog.log("capture", "stage_end", output=pcap_file, size_bytes=os.path.getsize(pcap_file), seconds=0)
                else:
                    print("\n[STAGE 1] Starting packet capture...")
                    StatusManager.update_status("Capture", "Starting packet capture...", 5)
                    t = time.time()
                    pcap_file = source.get_capture(cfgmod.get("capture.target_packets", 1000))
                    secs = time.time() - t
                    StatusManager.record_module_timing("Packet Capture", secs)
                    if not pcap_file:
                        return self._fail("Packet capture failed - aborting pipeline")
                    debuglog.log("capture", "stage_end", output=pcap_file, seconds=round(secs, 3),
                                 size_bytes=os.path.getsize(pcap_file) if os.path.exists(pcap_file) else None)
            else:
                pcap_file = STAGE_FILES["capture"]
                if not os.path.exists(pcap_file):
                    return self._fail(f"Cannot start from '{start_from}': {pcap_file} does not exist. Run the full pipeline first.")
            if stop_idx == 0:
                return self._stopped("capture")

            # ---------- STAGE 2: features ----------
            if start_idx <= 1:
                print("\n[STAGE 2] Feature extraction...")
                feature_file = self.extractor.extract_features(pcap_file)
                if not feature_file:
                    return self._fail("Feature extraction failed - aborting pipeline")
            else:
                feature_file = STAGE_FILES["features"]
                if not os.path.exists(feature_file):
                    return self._fail(f"Cannot start from '{start_from}': {feature_file} does not exist.")
            if stop_idx == 1:
                return self._stopped("features")

            # ---------- STAGE 3: sensitivity ----------
            if start_idx <= 2:
                print("\n[STAGE 3] Sensitivity analysis...")
                result_file = self.engine.classify_sensitivity(feature_file)
                if not result_file:
                    return self._fail("Sensitivity analysis failed - aborting pipeline")
            else:
                result_file = STAGE_FILES["sensitivity"]
                if not os.path.exists(result_file):
                    return self._fail(f"Cannot start from '{start_from}': {result_file} does not exist.")
            if stop_idx == 2:
                return self._stopped("sensitivity")

            # ---------- STAGE 4: policy ----------
            if start_idx <= 3:
                print("\n[STAGE 4] Policy decision engine...")
                policy_file = self.policy.select_policies(result_file, mode=mode, force_resource=force_resource)
                if not policy_file:
                    return self._fail("Policy engine failed - aborting pipeline")
            else:
                policy_file = STAGE_FILES["policy"]
                if not os.path.exists(policy_file):
                    return self._fail(f"Cannot start from '{start_from}': {policy_file} does not exist.")
            if stop_idx == 3:
                return self._stopped("policy")

            # ---------- STAGE 5: encryption ----------
            print("\n[STAGE 5] Encryption engine...")
            encrypted_file = self.encryptor.encrypt_traffic(policy_file, pcap_file)
            if not encrypted_file:
                return self._fail("Encryption engine failed - aborting pipeline")

            total_time = time.time() - self.total_start
            StatusManager.record_module_timing("Total Execution", total_time)
            msg = (f"✓ Pipeline Completed ({mode}) in {round(total_time, 2)} seconds | "
                   f"Outputs: {pcap_file}, {feature_file}, {result_file}, {policy_file}, {encrypted_file}")
            print(f"\n[SUCCESS] {msg}\n" + "=" * 60 + "\n")
            debuglog.log("pipeline", "run_end", seconds=round(total_time, 3), ok=True)
            StatusManager.update_status("Finished", msg, 100)
            return True

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return self._fail(f"Pipeline error: {str(e)}")

    def _stopped(self, stage):
        total = time.time() - self.total_start
        msg = f"✓ Stopped after '{stage}' as requested ({round(total, 2)} s). Inspect this step on the Debug page."
        debuglog.log("pipeline", "run_end", seconds=round(total, 3), ok=True, stopped_after=stage)
        StatusManager.update_status("Finished", msg, 100)
        print(f"[DEBUG] {msg}")
        return True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="adaptive", choices=["adaptive", "static_aes", "static_pqc"])
    ap.add_argument("--replay", default=None, help="existing pcap to reuse, e.g. data/traffic.pcapng")
    ap.add_argument("--force-resource", default=None, choices=["AVAILABLE", "CONSTRAINED"])
    ap.add_argument("--stop-after", default=None, choices=STAGES)
    ap.add_argument("--start-from", default=None, choices=STAGES)
    a = ap.parse_args()
    ok = PipelineController().run(mode=a.mode, replay_pcap=a.replay, force_resource=a.force_resource,
                                  stop_after=a.stop_after, start_from=a.start_from)
    exit(0 if ok else 1)
