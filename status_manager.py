import json
import os
import threading


class StatusManager:
    FILE = "data/status.json"
    TIMINGS_FILE = "data/timings.json"
    LOCK = threading.Lock()  # For thread-safe file operations

    @staticmethod
    def update_status(stage, message, progress=None):
        """Update the status JSON file"""
        try:
            os.makedirs("data", exist_ok=True)
            
            data = {
                "stage": stage,
                "message": message,
                "progress": progress if progress is not None else 0,
                "timestamp": __import__('time').time()
            }
            
            with StatusManager.LOCK:
                with open(StatusManager.FILE, "w") as f:
                    json.dump(data, f, indent=2)
            
            print(f"[STATUS] {stage}: {message} ({progress}%)" if progress is not None else f"[STATUS] {stage}: {message}")
            
        except Exception as e:
            print(f"[ERROR] Failed to update status: {e}")

    @staticmethod
    def get_status():
        """Get current status from JSON file"""
        try:
            if not os.path.exists(StatusManager.FILE):
                return {
                    "stage": "Idle",
                    "message": "Not started",
                    "progress": 0,
                    "timestamp": None
                }
            
            with StatusManager.LOCK:
                with open(StatusManager.FILE, "r") as f:
                    data = json.load(f)
                    return data
                    
        except (json.JSONDecodeError, ValueError, FileNotFoundError):
            return {
                "stage": "Idle",
                "message": "Error reading status",
                "progress": 0,
                "timestamp": None
            }
        except Exception as e:
            print(f"[ERROR] Failed to get status: {e}")
            return {
                "stage": "Error",
                "message": str(e),
                "progress": 0,
                "timestamp": None
            }

    @staticmethod
    def record_module_timing(module_name, execution_time):
        """Record how long a module took to execute"""
        try:
            os.makedirs("data", exist_ok=True)
            
            timings = {}
            
            # Read existing timings
            if os.path.exists(StatusManager.TIMINGS_FILE):
                try:
                    with StatusManager.LOCK:
                        with open(StatusManager.TIMINGS_FILE, "r") as f:
                            timings = json.load(f)
                except (json.JSONDecodeError, ValueError):
                    timings = {}
            
            # Initialize modules dict if needed
            if "modules" not in timings:
                timings["modules"] = {}
            
            # Record this module's timing
            timings["modules"][module_name] = round(execution_time, 2)
            
            # Calculate total time (excluding "Total Execution" to avoid double counting)
            total = sum(
                v for k, v in timings["modules"].items() 
                if k != "Total Execution"
            )
            timings["total"] = round(total, 2)
            
            # Write back
            with StatusManager.LOCK:
                with open(StatusManager.TIMINGS_FILE, "w") as f:
                    json.dump(timings, f, indent=2)
            
            print(f"[TIMING] {module_name}: {execution_time:.2f}s")
            
        except Exception as e:
            print(f"[ERROR] Failed to record timing: {e}")

    @staticmethod
    def clear_timings():
        """Clear timing data for fresh run"""
        try:
            if os.path.exists(StatusManager.TIMINGS_FILE):
                with StatusManager.LOCK:
                    os.remove(StatusManager.TIMINGS_FILE)
            print("[DEBUG] Timing data cleared")
        except Exception as e:
            print(f"[WARNING] Failed to clear timings: {e}")

    @staticmethod
    def clear_results():
        """Clear all output files for fresh run"""
        try:
            os.makedirs("data", exist_ok=True)
            
            files_to_clear = [
                "data/status.json",
                "data/timings.json",
                "data/traffic.pcapng",
                "data/features.csv",
                "data/results.csv",
                "data/policy.csv",
                "data/encrypted_results.csv"
            ]
            
            for file_path in files_to_clear:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"[WARNING] Could not remove {file_path}: {e}")
            
            print("[DEBUG] All output files cleared")
            
        except Exception as e:
            print(f"[ERROR] Failed to clear results: {e}")
