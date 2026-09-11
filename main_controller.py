from packet_capture import PacketCapture
from feature_extraction import FeatureExtractor
from sensitivity_engine import SensitivityEngine
from policy_engine import PolicyEngine
from encryption_engine import EncryptionEngine
from status_manager import StatusManager
import time


class PipelineController:
    def __init__(self):
        self.capture = PacketCapture()
        self.extractor = FeatureExtractor()
        self.engine = SensitivityEngine()
        self.policy = PolicyEngine()
        self.encryptor = EncryptionEngine()
        self.total_start = None

    def run(self):
        """Run the complete pipeline with proper status tracking"""
        self.total_start = time.time()
        
        try:
            # Clear previous timings
            StatusManager.clear_timings()
            
            print("\n" + "="*60)
            print("         PIPELINE EXECUTION STARTED")
            print("="*60)

            # ============ STAGE 1: PACKET CAPTURE ============
            print("\n[STAGE 1] Starting packet capture...")
            StatusManager.update_status("Capture", "Starting packet capture...", 5)
            
            capture_start = time.time()
            pcap_file = self.capture.capture_packets(1000)
            capture_time = time.time() - capture_start
            StatusManager.record_module_timing("Packet Capture", capture_time)

            if not pcap_file:
                error_msg = "Packet capture failed - aborting pipeline"
                print(f"[ERROR] {error_msg}")
                StatusManager.update_status("Error", error_msg)
                return False

            print(f"[SUCCESS] Packet capture completed: {pcap_file} ({capture_time:.2f}s)")

            # ============ STAGE 2: FEATURE EXTRACTION ============
            print("\n[STAGE 2] Starting feature extraction...")
            
            feature_file = self.extractor.extract_features(pcap_file)
            
            if not feature_file:
                error_msg = "Feature extraction failed - aborting pipeline"
                print(f"[ERROR] {error_msg}")
                StatusManager.update_status("Error", error_msg)
                return False

            print(f"[SUCCESS] Feature extraction completed: {feature_file}")

            # ============ STAGE 3: SENSITIVITY ANALYSIS ============
            print("\n[STAGE 3] Starting sensitivity analysis...")
            
            result_file = self.engine.classify_sensitivity(feature_file)
            
            if not result_file:
                error_msg = "Sensitivity analysis failed - aborting pipeline"
                print(f"[ERROR] {error_msg}")
                StatusManager.update_status("Error", error_msg)
                return False

            print(f"[SUCCESS] Sensitivity analysis completed: {result_file}")

            # ============ STAGE 4: POLICY ENGINE ============
            print("\n[STAGE 4] Starting policy decision engine...")

            policy_file = self.policy.select_policies(result_file)

            if not policy_file:
                error_msg = "Policy engine failed - aborting pipeline"
                print(f"[ERROR] {error_msg}")
                StatusManager.update_status("Error", error_msg)
                return False

            print(f"[SUCCESS] Policy engine completed: {policy_file}")

            # ============ STAGE 5: ENCRYPTION ENGINE ============
            print("\n[STAGE 5] Starting encryption engine...")

            encrypted_file = self.encryptor.encrypt_traffic(policy_file, pcap_file)

            if not encrypted_file:
                error_msg = "Encryption engine failed - aborting pipeline"
                print(f"[ERROR] {error_msg}")
                StatusManager.update_status("Error", error_msg)
                return False

            print(f"[SUCCESS] Encryption engine completed: {encrypted_file}")

            # ============ COMPLETION ============
            total_time = time.time() - self.total_start
            StatusManager.record_module_timing("Total Execution", total_time)

            message = (
                f"✓ Pipeline Completed Successfully in {round(total_time, 2)} seconds | "
                f"Outputs: {pcap_file}, {feature_file}, {result_file}, {policy_file}, {encrypted_file}"
            )
            
            print(f"\n[SUCCESS] {message}")
            print("="*60 + "\n")
            
            StatusManager.update_status("Finished", message, 100)
            return True

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            error_msg = f"Pipeline error: {str(e)}"
            
            print(f"\n[EXCEPTION] {error_msg}")
            print(error_trace)
            print("="*60 + "\n")
            
            StatusManager.update_status("Error", error_msg)
            return False


if __name__ == "__main__":
    controller = PipelineController()
    success = controller.run()
    exit(0 if success else 1)
