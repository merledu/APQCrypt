from flask import Flask, render_template, jsonify, send_file
import subprocess
import os
import pandas as pd
from status_manager import StatusManager
import threading
import json
import time

app = Flask(__name__)

# Store process references globally
mininet_process = None
pipeline_thread = None
pipeline_running = False

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

# ========== SAFETY CHECKS ==========
def check_sudo_access():
    """Check if user has sudo access without password"""
    try:
        result = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def check_mininet_installed():
    """Check if mininet is installed"""
    try:
        result = subprocess.run(["which", "mn"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def check_tshark_installed():
    """Check if tshark is installed"""
    try:
        result = subprocess.run(["which", "tshark"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

# ========== DIAGNOSTIC ENDPOINT ==========
@app.route("/diagnostics")
def diagnostics():
    """Check system requirements"""
    return jsonify({
        "sudo_access": check_sudo_access(),
        "mininet_installed": check_mininet_installed(),
        "tshark_installed": check_tshark_installed(),
        "data_dir_exists": os.path.isdir("data"),
        "message": "All checks required for pipeline to work"
    })

# ========== HOME ================
@app.route("/")
def home():
    return render_template("index.html")

# ========== START OSKEN MANAGER ================
@app.route("/start-osken")
def start_osken():
    try:
        # Check prerequisites
        if not check_sudo_access():
            return {"message": "Error: No sudo access. Run: sudo visudo (add NOPASSWD line)", "status": "error"}, 403
        
        if not check_mininet_installed():
            return {"message": "Error: Mininet not installed", "status": "error"}, 400
        
        # Clean up any previous instances
        try:
            subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=20)
            time.sleep(1)
        except Exception as e:
            print(f"Cleanup warning: {e}")

        StatusManager.update_status("OSKen", "OSKen Ready (OVS controller)", 0)
        return {"message": "OSKen Manager started successfully", "status": "started"}
    
    except Exception as e:
        error_msg = f"Error starting OSKen: {str(e)}"
        StatusManager.update_status("Error", error_msg)
        return {"message": error_msg, "status": "error"}, 500

# ========== STOP OSKEN MANAGER ================
@app.route("/stop-osken")
def stop_osken():
    global mininet_process, pipeline_running
    
    try:
        pipeline_running = False
        
        if mininet_process and mininet_process.poll() is None:
            mininet_process.terminate()
            mininet_process = None
        
        # Clean up mininet
        try:
            subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=15)
        except:
            pass
        
        StatusManager.update_status("OSKen", "OSKen Manager Stopped", 0)
        return {"message": "OSKen Manager stopped"}
    
    except Exception as e:
        return {"message": f"Error stopping OSKen: {str(e)}", "status": "error"}, 500

# ========== START PIPELINE ================
@app.route("/start-pipeline")
def start_pipeline():
    global pipeline_thread, pipeline_running
    
    if pipeline_running:
        return {"message": "Pipeline is already running", "status": "running"}, 409
    
    # Check prerequisites
    if not check_sudo_access():
        return {"message": "Error: No sudo access", "status": "error"}, 403
    
    if not check_mininet_installed():
        return {"message": "Error: Mininet not installed", "status": "error"}, 400
    
    if not check_tshark_installed():
        return {"message": "Error: tshark not installed", "status": "error"}, 400
    
    def run_pipeline():
        global pipeline_running
        from main_controller import PipelineController
        try:
            controller = PipelineController()
            controller.run()
        except Exception as e:
            import traceback
            traceback.print_exc()
            StatusManager.update_status("Error", f"Pipeline failed: {str(e)}")
        finally:
            pipeline_running = False

    pipeline_running = True
    pipeline_thread = threading.Thread(target=run_pipeline)
    pipeline_thread.daemon = True
    pipeline_thread.start()

    return {"message": "Pipeline started in background", "status": "running"}

# ========== STATUS ================
@app.route("/status")
def status():
    try:
        status_data = StatusManager.get_status()
        return jsonify(status_data)
    except Exception as e:
        print(f"Status error: {e}")
        return jsonify({
            "stage": "Idle",
            "message": "No status available",
            "progress": 0
        })

# ========== RESULTS ================
@app.route("/results")
def results():
    data = {
        "features": [],
        "protocols": {},
        "sensitivity": {},
        "policies": {},
        "algorithms": {},
        "resource_status": None,
        "total_packets": 0,
        "packet_file": None,
        "feature_file": None,
        "result_file": None,
        "policy_file": None,
        "encrypted_file": None,
        "encryption_summary": {},
        "module_timings": {},
        "total_time": 0
    }

    # -------- PACKET FILE --------
    if os.path.exists("data/traffic.pcapng"):
        try:
            file_size = os.path.getsize("data/traffic.pcapng")
            data["packet_file"] = f"data/traffic.pcapng ({file_size} bytes)"
        except:
            data["packet_file"] = "data/traffic.pcapng"

    # -------- FEATURES --------
    if os.path.exists("data/features.csv"):
        data["feature_file"] = "data/features.csv"
        try:
            df = pd.read_csv("data/features.csv")
            data["features"] = list(df.columns)
            data["total_packets"] = len(df)
            if "Protocol" in df.columns:
                data["protocols"] = df["Protocol"].value_counts().to_dict()
        except Exception as e:
            print(f"Feature file read error: {e}")

    # -------- RESULTS --------
    if os.path.exists("data/results.csv"):
        data["result_file"] = "data/results.csv"
        try:
            rdf = pd.read_csv("data/results.csv")
            if "Sensitivity" in rdf.columns:
                data["sensitivity"] = rdf["Sensitivity"].value_counts().to_dict()
        except Exception as e:
            print(f"Results file read error: {e}")

    # -------- POLICY DECISIONS --------
    if os.path.exists("data/policy.csv"):
        data["policy_file"] = "data/policy.csv"
        try:
            pdf = pd.read_csv("data/policy.csv")
            if "Selected_Policy" in pdf.columns:
                data["policies"] = pdf["Selected_Policy"].value_counts().to_dict()
            if "Selected_Algorithm" in pdf.columns:
                data["algorithms"] = pdf["Selected_Algorithm"].value_counts().to_dict()
            if "Resource_Status" in pdf.columns and len(pdf) > 0:
                data["resource_status"] = {
                    "status": pdf["Resource_Status"].iloc[0],
                    "cpu_percent": pdf["CPU_Percent"].iloc[0] if "CPU_Percent" in pdf.columns else None,
                    "memory_percent": pdf["Memory_Percent"].iloc[0] if "Memory_Percent" in pdf.columns else None,
                }
        except Exception as e:
            print(f"Policy file read error: {e}")

    # -------- ENCRYPTION RESULTS --------
    if os.path.exists("data/encrypted_results.csv"):
        data["encrypted_file"] = "data/encrypted_results.csv"
        try:
            edf = pd.read_csv("data/encrypted_results.csv")
            handshakes = edf[edf["New_Flow_Handshake"] == True]
            pqc_handshakes = handshakes[handshakes["PQC_Handshake_Used"] == True]
            data["encryption_summary"] = {
                "total_packets": len(edf),
                "total_flows": int(handshakes.shape[0]),
                "pqc_handshakes": int(pqc_handshakes.shape[0]),
                "total_handshake_ms": round(float(handshakes["Handshake_Time_ms"].sum()), 3),
                "total_encrypt_ms": round(float(edf["Encrypt_Time_us"].sum()) / 1000, 3),
                "total_ciphertext_bytes": int(edf["Ciphertext_Length"].sum()),
            }
        except Exception as e:
            print(f"Encrypted results read error: {e}")

    # -------- MODULE TIMINGS --------
    if os.path.exists("data/timings.json"):
        try:
            with open("data/timings.json", "r") as f:
                timings = json.load(f)
                data["module_timings"] = timings.get("modules", {})
                data["total_time"] = timings.get("total", 0)
        except Exception as e:
            print(f"Timings read error: {e}")

    return jsonify(data)

# ========== FILE DOWNLOAD ================
@app.route("/download/<file_type>")
def download_file(file_type):
    file_map = {
        "packets": "data/traffic.pcapng",
        "features": "data/features.csv",
        "results": "data/results.csv",
        "policy": "data/policy.csv",
        "encrypted": "data/encrypted_results.csv"
    }

    file_path = file_map.get(file_type)
    if file_path and os.path.exists(file_path):
        try:
            return send_file(file_path, as_attachment=True)
        except Exception as e:
            return {"error": f"Download failed: {str(e)}"}, 500

    return {"error": "File not found"}, 404

# ========== FILE VIEW ================
@app.route("/view/<file_type>")
def view_file(file_type):
    file_map = {
        "features": "data/features.csv",
        "results": "data/results.csv",
        "policy": "data/policy.csv",
        "encrypted": "data/encrypted_results.csv"
    }

    file_path = file_map.get(file_type)
    if file_path and os.path.exists(file_path):
        try:
            df = pd.read_csv(file_path)
            return jsonify({
                "columns": list(df.columns),
                "data": df.head(50).to_dict('records'),
                "total_rows": len(df)
            })
        except Exception as e:
            return {"error": f"File read error: {str(e)}"}, 500

    return {"error": "File not found"}, 404

# ========== ERROR HANDLERS ================
@app.errorhandler(404)
def not_found(e):
    return {"error": "Not found"}, 404

@app.errorhandler(500)
def server_error(e):
    return {"error": "Server error"}, 500

# ========== RUN ================
if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    print("\n" + "="*50)
    print("        PIPELINE SERVER STARTING")
    print("="*50)
    print(f"✓ Data directory: {os.path.abspath('data')}")
    print(f"✓ Sudo access: {check_sudo_access()}")
    print(f"✓ Mininet installed: {check_mininet_installed()}")
    print(f"✓ Tshark installed: {check_tshark_installed()}")
    print("="*50 + "\n")
    
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True
    )
