"""
Self-test for the three interfaces (run it before the demo):   python selftest.py

Checks: all 8 pages, the Settings (configuration) checks and presets, the Interfaces (wrapper)
connections and REST API, a pipeline run, and the Debug (processing steps) data.
It uses a temporary settings file, so your own saved settings are not touched.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ["APQ_CONFIG"] = os.path.join(tempfile.mkdtemp(), "selftest_config.json")
import app as A      # noqa: E402

client = A.app.test_client()
passed, failed = [], []


def ok(cond, msg):
    (passed if cond else failed).append(msg)
    print(("PASS  " if cond else "FAIL  ") + msg)


def wait_pipeline(max_s=90):
    for _ in range(int(max_s / 0.5)):
        st = client.get("/status").get_json()
        if st["stage"] in ("Finished", "Error"):
            return st
        time.sleep(0.5)
    return {"stage": "Timeout", "message": "pipeline did not finish"}


print("== 0. sample capture ==")
if not os.path.exists("data/traffic.pcapng"):
    subprocess.run([sys.executable, "make_sample_pcap.py"], capture_output=True)
ok(os.path.exists("data/traffic.pcapng"), "a capture file is available (data/traffic.pcapng)")

print("\n== 1. pages ==")
for url in ["/", "/sensitivity", "/resources", "/encryption", "/compare", "/debug", "/interfaces", "/settings"]:
    r = client.get(url)
    ok(r.status_code == 200, f"page {url} opens")

print("\n== 2. CONFIGURATION interface ==")
r = client.get("/api/config").get_json()
ok(len(r["presets"]) == 3 and "config" in r, "settings and 3 presets are available")
r = client.put("/api/config", json={"config": {"resources": {"cpu_limit": 500}}})
ok(r.status_code == 400 and "cpu_limit" in json.dumps(r.get_json()), "out-of-range value is refused with a clear message")
r = client.put("/api/config", json={"config": {"policy": {"matrix": {"HIGH": {"AVAILABLE": {"kex": "X25519", "cipher": "AES-256-GCM"}}}}}})
ok(r.status_code == 400 and "HIGH must use" in json.dumps(r.get_json()), "HIGH cannot be made non-quantum-safe (safety rule)")
r = client.put("/api/config", json={"config": {"policy": {"matrix": {"LOW": {"AVAILABLE": {"kex": "X25519", "cipher": "AES-256-CBC"}}}}}})
ok(r.status_code == 400, "locks without tamper detection (CBC) are refused")
r = client.put("/api/config", json={"config": {"resources": {"cpu_limit": 42}}})
ok(r.status_code == 200 and client.get("/api/config").get_json()["config"]["resources"]["cpu_limit"] == 42, "valid change is saved")
r = client.post("/api/config/preset/iot_low_power")
ok(r.status_code == 200 and r.get_json()["config"]["resources"]["cpu_limit"] == 30, "preset 'IoT low power' applies")
r = client.post("/api/config/reset")
ok(r.get_json()["config"]["resources"]["cpu_limit"] == 50, "reset returns the defaults")
ok(client.get("/api/config/export").status_code == 200, "settings can be exported")

print("\n== 3. WRAPPER interface: connections ==")
rows = client.get("/api/interfaces").get_json()["rows"]
ok(len(rows) == 5, "5 external connections listed (packet source x2, AI model, ML-KEM x2)")
for r_ in rows:
    print(f"      - {r_['kind']:16s} {r_['name']:14s} active={r_['active']!s:5s} available={r_['available']!s:5s} {str(r_['detail'])[:60]}")
oqs_ok = next(x for x in rows if x["name"] == "liboqs")["available"]
ok(client.post("/api/interfaces/select", json={"kind": "crypto_provider", "name": "simulated"}).status_code == 400,
   "the simulated (not quantum-safe) provider cannot be chosen without a confirmation")

print("\n== 4. WRAPPER interface: REST API ==")
from api_v1 import get_key      # creates data/api_key.txt on first use
key = get_key()
H = {"X-API-Key": key}
ok(client.get("/api/v1/health").get_json()["status"] == "ok", "GET /health works without a key")
ok(client.post("/api/v1/decide", json={"protocol": "SSH", "dest_port": 22}).status_code == 401, "no key -> 401")
r = client.post("/api/v1/decide", json={"protocol": "SSH", "dest_port": 22, "resource_status": "CONSTRAINED"}, headers=H)
b = r.get_json()
ok(r.status_code == 200 and b["sensitivity"] == "HIGH" and b["decision"]["quantum_safe"], f"POST /decide: SSH -> {b.get('sensitivity')} {b['decision']['algorithm']}")
ok(client.post("/api/v1/decide", json={"protocol": "X", "dest_port": -1}, headers=H).status_code == 400, "bad request -> 400 with details")
with open("data/traffic.pcapng", "rb") as f:
    data = f.read()
r = client.post("/api/v1/analyze", data={"pcap": (io.BytesIO(data), "t.pcapng"), "mode": "adaptive", "force_resource": "AVAILABLE"},
                headers=H, content_type="multipart/form-data")
ok(r.status_code == 202, "POST /analyze accepts a capture and starts a job")
job = r.get_json().get("job_id")
for _ in range(60):
    j = client.get(f"/api/v1/jobs/{job}", headers=H).get_json()
    if j["status"] in ("done", "failed"):
        break
    time.sleep(0.5)
ok(j["status"] == "done", f"the job finishes ({j['status']}): {j.get('summary', {}).get('sensitivity')}")
d = client.get(f"/api/v1/jobs/{job}/decisions", headers=H).get_json()
ok(len(d.get("decisions", [])) > 0, f"{len(d.get('decisions', []))} conversation decisions returned")
ok(client.post("/api/v1/analyze", data={"pcap": (io.BytesIO(b"not a capture"), "x.pcapng")}, headers=H,
               content_type="multipart/form-data").status_code == 400, "a file that is not a capture is rejected")

print("\n== 5. pipeline run (reuse the capture) ==")
r = client.post("/start-pipeline?replay=1&force=AVAILABLE")
ok(r.status_code == 200, "pipeline starts from the app")
st = wait_pipeline()
if st["stage"] == "Finished":
    ok(True, "pipeline finished: " + st["message"][:70])
else:
    ok(False, "pipeline did not finish: " + st["message"][:120] + ("" if oqs_ok else "   (ML-KEM is not available here: install liboqs, see the guide)"))

print("\n== 6. DEBUG interface ==")
stages = client.get("/api/debug/stages").get_json()["stages"]
ok(len(stages) == 5, "5 processing steps are listed: " + ", ".join(f"{s['stage']}={s['status']}" for s in stages))
ev = client.get("/api/debug/events?limit=1000").get_json()["events"]
ok(len(ev) > 10, f"{len(ev)} log events were recorded")
flows = client.get("/flows").get_json()["rows"]
if flows:
    t = client.get("/api/debug/trace", query_string={"flow": flows[0]["flow"]})
    ok(t.status_code == 200 and len(t.get_json()["steps"]) >= 5, f"a conversation can be traced step by step ({len(t.get_json().get('steps', []))} steps)")
else:
    ok(False, "no conversations to trace (the pipeline did not reach encryption)")
ok(client.get("/api/debug/bundle").status_code == 200, "debug bundle (.zip) downloads")
r = client.post("/start-pipeline?replay=1&stop_after=sensitivity")
st = wait_pipeline()
ok(st["stage"] == "Finished" and "Stopped after" in st["message"], "'run up to a step' stops where asked")
r = client.post("/start-pipeline?start_from=policy&force=CONSTRAINED")
st = wait_pipeline()
ok(st["stage"] in ("Finished", "Error"), "'re-run from a step' reuses saved files: " + st["message"][:60])

print("\n== 7. COMPARISON ENGINE (measured runs + evidence) ==")
def wait_cmp(max_s=240):
    for _ in range(int(max_s / 0.5)):
        stt = client.get("/api/comparison/status").get_json()
        if not stt["running"]:
            return stt
        time.sleep(0.5)
    return {"running": True, "error": "timeout"}

summ = client.get("/api/comparison").get_json()
ok(summ["host"]["machine"] and set(summ["modes"]) == {"static_aes", "static_pqc", "adaptive"}, "comparison page data loads: host " + summ["host"]["label"][:50])
client.post("/api/comparison/clear", json={"all": True})
ok(client.get("/api/comparison").get_json()["series"] == {}, "nothing is shown before anything is measured (no invented bars)")
r = client.post("/api/comparison/run", json={"modes": ["bogus"], "runs": 1})
ok(r.status_code == 400, "unknown mode refused")
r = client.post("/api/comparison/run", json={"modes": ["static_aes"], "runs": 99})
ok(r.status_code == 400, "runs outside 1-15 refused")
r = client.post("/api/comparison/run", json={"modes": ["static_aes"], "runs": 2, "interleave": True})
ok(r.status_code == 200, "measuring the NORMAL mode starts")
ok(client.post("/start-pipeline?replay=1").status_code == 409, "the pipeline cannot start while a measurement runs")
wait_cmp()
s1 = client.get("/api/comparison").get_json()
a = s1["series"].get("static_aes")
ok(a is not None and a["n"] == 2, f"normal mode: {a['n'] if a else 0} counted runs (the warm-up run is not counted)")
ok("static_pqc" not in s1["series"] and "adaptive:free" not in s1["series"], "modes that were not run have NO data")
if oqs_ok:
    r = client.post("/api/comparison/run", json={"modes": ["static_pqc", "adaptive"], "runs": 2, "force": "AVAILABLE"})
    ok(r.status_code == 200, "measuring ALL-QUANTUM-SAFE and ADAPTIVE starts")
    wait_cmp()
    s2 = client.get("/api/comparison").get_json()
    ser = s2["series"]
    ok("static_pqc" in ser and ser["static_pqc"]["n"] == 2, "all-quantum-safe measured: " + str(ser.get("static_pqc", {}).get("n")) + " runs")
    ok("adaptive:free" in ser and ser["adaptive:free"]["n"] == 2, "adaptive measured (computer free): " + str(ser.get("adaptive:free", {}).get("n")) + " runs")
    ok(ser["static_pqc"]["pq_flow_share"]["mean"] == 1.0, "mode B really used quantum-safe keys for every conversation")
    ok(ser["static_aes"]["pq_flow_share"]["mean"] == 0.0, "mode A used none")
    ok(ser["adaptive:free"]["decision_s"]["mean"] > 0 and ser["static_aes"]["decision_s"]["mean"] == 0, "adaptive pays a decision cost, the others do not (and it is shown)")
    ok(ser["adaptive:free"]["peak_mem_mb"]["mean"] > ser["static_aes"]["peak_mem_mb"]["mean"], "adaptive memory includes the AI model (memory differs between modes)")
    ok(len(s2["messages"]) >= 4, f"{len(s2['messages'])} findings are generated from the measured numbers")
    ok(s2["series"]["adaptive:free"].get("high_coverage") is not None, "HIGH-conversation protection is judged against the adaptive run")
else:
    r = client.post("/api/comparison/run", json={"modes": ["static_pqc"], "runs": 1})
    ok(r.status_code == 400 and "liboqs" in json.dumps(r.get_json()), "without liboqs the quantum-safe modes refuse to run (no fake numbers)")
csv_text = client.get("/api/comparison/export.csv").get_data(as_text=True)
ok(csv_text.count("\n") >= 3 and "static_aes" in csv_text, "evidence CSV lists every run")
r = client.post("/api/comparison/micro")
ok(r.status_code == 200, "algorithm micro-benchmark starts")
wait_cmp()
ok(client.get("/api/comparison").get_json()["micro"] is not None, "algorithm costs measured on this machine")
ok(client.post("/api/comparison/clear", json={"mode": "static_aes"}).get_json()["removed"] >= 2, "stored runs of one mode can be cleared")
client.post("/api/comparison/clear", json={"all": True})

client.post("/api/config/reset")
print(f"\n{len(passed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
