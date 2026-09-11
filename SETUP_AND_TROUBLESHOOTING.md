# SETUP & TROUBLESHOOTING GUIDE

## ⚡ QUICK START (5 minutes)

### 1. Install Dependencies
```bash
# Install Python packages
pip install -r requirements.txt

# Install system packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tshark
```

### 2. Configure Sudo (CRITICAL!)
Without this, you'll get permission errors:

```bash
# Open sudoers file safely
sudo visudo

# Add this line at the end (replace 'username' with your actual username):
username ALL=(ALL) NOPASSWD: /usr/bin/mn, /usr/bin/python3, /usr/sbin/tshark, /usr/bin/tshark, /bin/cp, /bin/rm, /usr/bin/chown, /usr/bin/chmod
```

Or use this one-liner (SAFER):
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/mn, /usr/bin/python3, /usr/sbin/tshark, /usr/bin/tshark, /bin/cp, /bin/rm, /usr/bin/chown, /usr/bin/chmod" | sudo tee -a /etc/sudoers.d/pipeline
```

### 3. Run Diagnostics
```bash
# Check if everything is installed
python3 -c "from app import check_sudo_access, check_mininet_installed, check_tshark_installed; print('Sudo:', check_sudo_access()); print('Mininet:', check_mininet_installed()); print('Tshark:', check_tshark_installed())"

# All three should print True
```

### 4. Start the Server
```bash
python3 app.py
# Server starts at http://localhost:5000
```

---

## 🔧 COMMON ISSUES & FIXES

### ❌ "Error: sudo access denied"
**Problem**: Flask doesn't have permission to run Mininet and tshark

**Solution**:
```bash
# Test if you have passwordless sudo for needed commands
sudo -n mn -c

# If that fails, configure sudoers (see setup step 2)
sudo visudo
# Add: username ALL=(ALL) NOPASSWD: /usr/bin/mn, /usr/bin/python3, /usr/sbin/tshark, /usr/bin/tshark, /bin/cp, /bin/rm, /usr/bin/chown, /usr/bin/chmod
```

### ❌ "Mininet not found"
**Problem**: Mininet is not installed

**Solution**:
```bash
# Install Mininet
sudo apt-get install -y mininet

# Verify installation
mn --help

# If still not found, check your PATH
which mn
```

### ❌ "tshark not found"
**Problem**: Wireshark tools not installed

**Solution**:
```bash
# Install Wireshark (includes tshark)
sudo apt-get install -y tshark

# Verify installation
tshark --version

# Give user permission to use tshark
sudo usermod -a -G wireshark $(whoami)
# LOGOUT AND LOGIN after this!
```

### ❌ "No packets captured"
**Problem**: Packet capture ran but captured 0 packets

**Causes & Fixes**:
1. **Interface not found**
   - Check if switch has correct interface
   - Look at debug output: `[DEBUG] Using interface: ...`
   - Try using first available interface instead

2. **Traffic not generating**
   - Ping might be failing
   - Check mininet hosts are connected
   - Increase ping count in capture_packets()

3. **tshark not capturing**
   - Check interface is correct
   - Verify tshark permissions
   - Try manual test:
   ```bash
   sudo tshark -i eth0 -w /tmp/test.pcapng -a packets:10 -a duration:5
   ```

**Debug steps**:
```bash
# Check the debug output in terminal
# Look for: [DEBUG] Using interface: ...
# Look for: TSHARK Return Code: 0 (success) or error messages

# Manually test mininet
sudo mn -c
sudo python3 -c "
from mininet.net import Mininet
from mininet.topo import Topo

class TestTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')
        self.addLink(h1, s1)
        self.addLink(h2, s1)

net = Mininet(topo=TestTopo(), controller=None)
net.start()
h1 = net.get('h1')
h2 = net.get('h2')
print('Host IPs:', h1.IP(), h2.IP())
net.stop()
"
```

### ❌ "Scapy error / IP packet not found"
**Problem**: Feature extraction can't parse packets

**Solution**:
```bash
# Reinstall scapy with latest version
pip install --upgrade scapy

# Verify installation
python3 -c "from scapy.all import IP, TCP, UDP, rdpcap; print('Scapy OK')"
```

### ❌ "Model not found: sensitivity_model.pkl"
**Problem**: ML model file is missing

**Solution**:
```bash
# Check if model exists
ls -la sensitivity_model.pkl

# If missing:
# 1. Copy from backup location
# 2. Or train a new model using your training script
# 3. Or ask for the model file

# The code now searches multiple locations:
# - sensitivity_model.pkl (current directory)
# - data/sensitivity_model.pkl
# - /app/sensitivity_model.pkl
# - ~/sensitivity_model.pkl
```

### ❌ "Permission denied" on data files
**Problem**: Files created by sudo can't be read/modified by user

**Solution**:
```bash
# Fix ownership of data directory
sudo chown -R $(whoami):$(whoami) data/

# Fix permissions
sudo chmod -R 755 data/

# This is handled automatically in the fixed code
```

### ❌ "Pipeline hangs/timeout"
**Problem**: Pipeline takes too long or hangs

**Cause & Fix**:
- Mininet capture timeout: Increase timeout in packet_capture.py (line ~70)
- Too many packets: Reduce count in `/start-pipeline` route
- System too slow: Reduce packet count from 100 to 50

```python
# In packet_capture.py, change:
pcap_file = self.capture.capture_packets(100)  # Change 100 to 50
```

### ❌ Flask port 5000 already in use
**Problem**: "Address already in use"

**Solution**:
```bash
# Find what's using port 5000
sudo lsof -i :5000

# Kill the process (replace PID with actual number)
kill -9 <PID>

# Or change port in app.py:
# Change: app.run(host="0.0.0.0", port=5000)
# To:     app.run(host="0.0.0.0", port=5001)
```

### ❌ JSON decode error in status
**Problem**: Status file is corrupted

**Solution**:
```bash
# Delete corrupted files
rm data/status.json
rm data/timings.json

# Restart server
python3 app.py
```

---

## 🧪 TESTING

### Test 1: Diagnostics
```bash
curl http://localhost:5000/diagnostics
```

Should return:
```json
{
  "sudo_access": true,
  "mininet_installed": true,
  "tshark_installed": true,
  "data_dir_exists": true,
  "message": "All checks required for pipeline to work"
}
```

### Test 2: Start/Stop OSKen
```bash
# Start
curl http://localhost:5000/start-osken

# Check status
curl http://localhost:5000/status

# Stop
curl http://localhost:5000/stop-osken
```

### Test 3: Run Pipeline
```bash
# Start pipeline
curl http://localhost:5000/start-pipeline

# Check status (repeat every 5 seconds)
curl http://localhost:5000/status

# Get results
curl http://localhost:5000/results
```

### Test 4: View Data
```bash
# View features (first 50 rows)
curl http://localhost:5000/view/features

# View results
curl http://localhost:5000/view/results

# Download files
curl http://localhost:5000/download/packets -o traffic.pcapng
curl http://localhost:5000/download/features -o features.csv
curl http://localhost:5000/download/results -o results.csv
```

---

## 📋 ARCHITECTURE FIXED

### Files Provided:
1. **app.py** - Flask server with diagnostics and proper process management
2. **packet_capture.py** - Mininet-based packet capture with better timing/interface detection
3. **feature_extraction.py** - Scapy-based feature extraction with error handling
4. **sensitivity_engine.py** - ML model integration with proper error messages
5. **main_controller.py** - Pipeline orchestration with logging
6. **status_manager.py** - Thread-safe status and timing management
7. **requirements.txt** - All Python dependencies

### Key Improvements:
✅ Proper sudo access checking
✅ Better error messages and debugging
✅ Thread-safe file operations
✅ Timeout handling for all subprocess calls
✅ Graceful fallback for missing files
✅ Comprehensive logging
✅ Model path search in multiple locations
✅ File permission fixes automatically

---

## 🚀 FULL PIPELINE TEST

```bash
# 1. Clean slate
rm -rf data/*

# 2. Start server
python3 app.py &
sleep 2

# 3. Check diagnostics
curl http://localhost:5000/diagnostics

# 4. Start OSKen
curl http://localhost:5000/start-osken

# 5. Run pipeline
curl http://localhost:5000/start-pipeline

# 6. Monitor (repeat every 5 seconds until progress = 100)
watch -n 1 'curl -s http://localhost:5000/status | python3 -m json.tool'

# 7. Check results
curl http://localhost:5000/results

# 8. Download outputs
curl http://localhost:5000/download/features -o features.csv
curl http://localhost:5000/download/results -o results.csv
```

---

## 📞 STILL HAVING ISSUES?

1. Check the console output for `[DEBUG]` messages
2. Check `/tmp/mininet_capture.py` for Mininet script details
3. Verify sudoers configuration: `sudo -l`
4. Check file permissions: `ls -la data/`
5. Verify installed tools: `mn --help`, `tshark --version`, `python3 -c "import scapy"`

**If stuck**: Clean and retry
```bash
rm -rf data/*
sudo mn -c
python3 app.py
```
