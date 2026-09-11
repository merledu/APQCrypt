# ⚡ QUICK REFERENCE CARD

## 🚀 QUICK START (Copy-Paste)

```bash
# 1. Install everything (one-time)
pip install -r requirements.txt
sudo apt-get install -y mininet openvswitch-switch tshark

# 2. Configure passwordless sudo (CRITICAL!)
echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/mn, /usr/bin/python3, /usr/sbin/tshark, /usr/bin/tshark, /bin/cp, /bin/rm, /usr/bin/chown, /usr/bin/chmod" | sudo tee -a /etc/sudoers.d/pipeline

# 3. Start server
python3 app.py

# 4. In another terminal, test pipeline
curl http://localhost:5000/start-pipeline
curl http://localhost:5000/status  # Repeat until progress=100
curl http://localhost:5000/results
```

---

## 🔍 DIAGNOSTIC COMMANDS

```bash
# Check if everything is installed
curl http://localhost:5000/diagnostics

# Expected output:
# {
#   "sudo_access": true,
#   "mininet_installed": true,
#   "tshark_installed": true,
#   "data_dir_exists": true
# }
```

---

## 🎮 BASIC OPERATIONS

```bash
# START OSKen
curl http://localhost:5000/start-osken

# STOP OSKen
curl http://localhost:5000/stop-osken

# RUN PIPELINE
curl http://localhost:5000/start-pipeline

# CHECK STATUS (repeat every 5 seconds)
curl http://localhost:5000/status

# VIEW RESULTS
curl http://localhost:5000/results

# VIEW FEATURES (first 50 rows)
curl http://localhost:5000/view/features

# VIEW CLASSIFICATION RESULTS
curl http://localhost:5000/view/results

# DOWNLOAD FILES
curl http://localhost:5000/download/packets -o traffic.pcapng
curl http://localhost:5000/download/features -o features.csv
curl http://localhost:5000/download/results -o results.csv
```

---

## 🐛 QUICK TROUBLESHOOTING

### "sudo access denied"
```bash
sudo -n mn -c  # Test passwordless sudo
# If fails, run setup step 2 again
```

### "Mininet not found"
```bash
which mn  # Should show /usr/bin/mn
# If not found, run: sudo apt-get install -y mininet
```

### "tshark not found"
```bash
which tshark  # Should show /usr/sbin/tshark
# If not found, run: sudo apt-get install -y tshark
# Then logout and login
```

### "No packets captured"
```bash
# Check debug output in terminal for [DEBUG] messages
# Look for: "Using interface: s1-eth1"
# If no interface, that's the problem
```

### "Model not found"
```bash
ls -la sensitivity_model.pkl  # Check if file exists
# If not, copy from backup or ask for model file
```

### "Port 5000 already in use"
```bash
sudo lsof -i :5000  # Find process using port
kill -9 <PID>       # Kill it
# OR change port in app.py
```

### "Permission denied" on data files
```bash
sudo chown -R $(whoami):$(whoami) data/
# Fixed automatically in new code
```

---

## 📊 FILE LOCATIONS

```
Project Root:
├── app.py                           # Flask server
├── packet_capture.py                # Mininet capture
├── feature_extraction.py            # Scapy feature extraction
├── sensitivity_engine.py            # ML classification
├── main_controller.py               # Pipeline orchestration
├── status_manager.py                # Status/timing tracking
├── sensitivity_model.pkl            # ML model (MUST EXIST!)
├── requirements.txt                 # Python dependencies
├── SETUP_AND_TROUBLESHOOTING.md     # Detailed guide
├── ISSUES_FOUND_AND_FIXED.md        # What was fixed
├── QUICK_REFERENCE.md               # This file
└── data/
    ├── traffic.pcapng               # Captured packets
    ├── features.csv                 # Extracted features
    ├── results.csv                  # Classification results
    ├── status.json                  # Current status
    └── timings.json                 # Module execution times
```

---

## 📈 EXPECTED PIPELINE OUTPUT

```
[STAGE 1] Packet Capture
- Duration: 20-30 seconds
- Output: data/traffic.pcapng (100+ KB)
- Status: ✓ Captured N packets

[STAGE 2] Feature Extraction
- Duration: 5-10 seconds
- Output: data/features.csv (50+ KB)
- Status: ✓ Extracted features: N packets

[STAGE 3] Sensitivity Analysis
- Duration: 10-15 seconds
- Output: data/results.csv (100+ KB)
- Status: ✓ Sensitivity Analysis Complete

[TOTAL] 40-60 seconds end-to-end
```

---

## 🔧 KEY FIXES APPLIED

✅ Interface detection now has fallback
✅ Timing fixed for traffic generation
✅ Process management properly initialized
✅ Model path searches multiple locations
✅ Scapy imports properly checked
✅ File permissions automatically fixed
✅ Status manager is thread-safe
✅ Sudo access verified on startup
✅ Comprehensive error handling added
✅ Detailed debug logging throughout

---

## ⚙️ CONFIGURATION

### Packet Count
```python
# In app.py, /start-pipeline route:
pcap_file = self.capture.capture_packets(100)  # Change 100 to other number
```

### Capture Timeout
```python
# In packet_capture.py:
timeout=120  # seconds, change if needed
```

### Server Port
```python
# In app.py, bottom of file:
app.run(host="0.0.0.0", port=5000)  # Change port here
```

---

## 🧪 UNIT TESTS

```bash
# Test 1: Mininet is working
sudo python3 -c "from mininet.net import Mininet; print('Mininet OK')"

# Test 2: Scapy is working
python3 -c "from scapy.all import IP, TCP, UDP, rdpcap; print('Scapy OK')"

# Test 3: Model file exists
python3 -c "import pickle; open('sensitivity_model.pkl').close(); print('Model OK')"

# Test 4: Server responds
curl http://localhost:5000/diagnostics

# Test 5: Full pipeline
curl http://localhost:5000/start-pipeline && sleep 60 && curl http://localhost:5000/results
```

---

## 📝 MONITORING

```bash
# Watch status in real-time
watch -n 1 'curl -s http://localhost:5000/status | python3 -m json.tool'

# Monitor file sizes
watch -n 2 'du -sh data/*'

# Monitor process
ps aux | grep python3

# Check error logs (if redirected)
tail -f error.log
```

---

## 🆘 NUCLEAR OPTIONS (Last Resort)

```bash
# Stop everything
killall python3
sudo mn -c

# Clean and restart
rm -rf data/*
python3 app.py

# Reset sudoers
sudo visudo  # Remove any problematic lines

# Full system reset
sudo apt-get remove -y mininet openvswitch-switch tshark
sudo apt-get install -y mininet openvswitch-switch tshark
```

---

**Need more help?** See `SETUP_AND_TROUBLESHOOTING.md` for detailed info.

**Found a bug?** Check `ISSUES_FOUND_AND_FIXED.md` for what was fixed.
