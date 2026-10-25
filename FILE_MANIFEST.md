# 📦 FILE MANIFEST - COMPLETE GUIDE

## All Files Provided (Ready to Use!)

### Core Application Files (MUST HAVE)

| File | Purpose | Status | Critical |
|------|---------|--------|----------|
| **app.py** | Flask web server with diagnostics | ✅ FIXED | 🔴 YES |
| **packet_capture.py** | Mininet-based packet capture | ✅ FIXED | 🔴 YES |
| **feature_extraction.py** | Scapy-based feature extraction | ✅ FIXED | 🔴 YES |
| **sensitivity_engine.py** | ML model for classification | ✅ FIXED | 🔴 YES |
| **main_controller.py** | Pipeline orchestration | ✅ FIXED | 🔴 YES |
| **status_manager.py** | Status and timing management | ✅ FIXED | 🔴 YES |

### Dependencies File

| File | Purpose | Status |
|------|---------|--------|
| **requirements.txt** | Python package list | ✅ PROVIDED |

### Documentation Files

| File | Purpose | Pages | Format |
|------|---------|-------|--------|
| **SETUP_AND_TROUBLESHOOTING.md** | Complete setup guide + 15 common issues | 10+ | Markdown |
| **ISSUES_FOUND_AND_FIXED.md** | What was wrong and how fixed | 16 issues | Markdown |
| **QUICK_REFERENCE.md** | Quick commands and cheatsheet | 1-2 page | Markdown |
| **FILE_MANIFEST.md** | This file - index of all files | 1-2 page | Markdown |

---

## 🎯 DIRECTORY STRUCTURE

After setup, your directory should look like:

```
~/ (or /home/username/)
├── app.py                              ← START HERE
├── packet_capture.py                   
├── feature_extraction.py               
├── sensitivity_engine.py               
├── main_controller.py                  
├── status_manager.py                   
├── sensitivity_model.pkl               ← MUST EXIST!
├── requirements.txt                    
│
├── SETUP_AND_TROUBLESHOOTING.md       (Documentation)
├── ISSUES_FOUND_AND_FIXED.md          (Documentation)
├── QUICK_REFERENCE.md                 (Documentation)
├── FILE_MANIFEST.md                   (Documentation - this)
│
├── data/                               (Created automatically)
│   ├── traffic.pcapng                  (Generated: packets)
│   ├── features.csv                    (Generated: features)
│   ├── results.csv                     (Generated: results)
│   ├── status.json                     (Generated: status)
│   └── timings.json                    (Generated: timings)
│
└── templates/                          (If using HTML frontend)
    └── index.html                      (Optional: frontend)
```

---

## 📥 INSTALLATION CHECKLIST

### Step 1: Copy All Python Files
```bash
# Copy to your working directory
cp app.py .
cp packet_capture.py .
cp feature_extraction.py .
cp sensitivity_engine.py .
cp main_controller.py .
cp status_manager.py .
cp requirements.txt .

# ⚠️ CRITICAL: Copy or get sensitivity_model.pkl
# This file MUST exist! Ask for it if you don't have it
cp /path/to/sensitivity_model.pkl .
```

### Step 2: Install Dependencies
```bash
# Python packages
pip install -r requirements.txt

# System packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tshark
```

### Step 3: Configure Sudo
```bash
# Allow passwordless sudo for required commands
echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/mn, /usr/bin/python3, /usr/sbin/tshark, /usr/bin/tshark, /bin/cp, /bin/rm, /usr/bin/chown, /usr/bin/chmod" | sudo tee -a /etc/sudoers.d/pipeline
```

### Step 4: Verify Installation
```bash
# Check all requirements met
python3 app.py

# Should show:
# ==================================================
#         PIPELINE SERVER STARTING
# ==================================================
# ✓ Data directory: ...
# ✓ Sudo access: True
# ✓ Mininet installed: True
# ✓ Tshark installed: True
# ==================================================
```

---

## 📋 WHAT EACH FILE DOES

### 1. **app.py** (Main Flask Server)
**Purpose**: Web server that provides REST API endpoints
**Key Features**:
- Diagnostic endpoint: `/diagnostics` - checks all requirements
- Control endpoints: `/start-osken`, `/stop-osken`
- Pipeline endpoint: `/start-pipeline`
- Status endpoint: `/status`
- Results endpoints: `/results`, `/view/<type>`, `/download/<type>`
**Fixed Issues**: Process management, sudo checking, error handling
**Dependencies**: Flask, pandas, status_manager

---

### 2. **packet_capture.py** (Mininet Packet Capture)
**Purpose**: Captures network packets using Mininet and tshark
**Key Features**:
- Creates 2-host Mininet topology
- Starts ping traffic between hosts
- Captures on switch interface with tshark
- Validates and counts captured packets
**Fixed Issues**: Interface detection, timing, return codes, file permissions
**Dependencies**: subprocess, os, time, status_manager

---

### 3. **feature_extraction.py** (Scapy Feature Extraction)
**Purpose**: Parses PCAP file and extracts network features
**Key Features**:
- Reads PCAP file with Scapy
- Extracts: Source IP, Dest IP, Ports, Protocol, TTL, Flags, etc.
- Validates packets and handles errors gracefully
- Outputs features.csv
**Fixed Issues**: Scapy import checking, error handling, validation
**Dependencies**: scapy, pandas, status_manager

---

### 4. **sensitivity_engine.py** (ML Classification)
**Purpose**: Applies ML model to classify packet sensitivity
**Key Features**:
- Loads pre-trained Random Forest model
- Calculates confidentiality score based on ports
- Applies risk model for prediction
- Fuses both scores for final sensitivity classification
- Outputs results.csv with detailed breakdown
**Fixed Issues**: Model path search, error handling, input validation
**Dependencies**: pickle, pandas, numpy, sklearn, status_manager

---

### 5. **main_controller.py** (Pipeline Orchestration)
**Purpose**: Coordinates all pipeline stages
**Key Features**:
- Runs capture → extraction → sensitivity in sequence
- Tracks timing for each stage
- Provides detailed logging
- Returns success/failure status
**Fixed Issues**: Logging, error propagation, status tracking
**Dependencies**: packet_capture, feature_extraction, sensitivity_engine, status_manager

---

### 6. **status_manager.py** (Status & Timing Management)
**Purpose**: Thread-safe status and timing tracking
**Key Features**:
- Updates status.json during execution
- Records module execution times
- Thread-safe file operations with locks
- Provides fallback if file missing/corrupted
**Fixed Issues**: Thread safety, locking, error handling
**Dependencies**: json, os, threading

---

### 7. **requirements.txt** (Python Dependencies)
**Contents**:
```
Flask==2.3.2          # Web framework
pandas==1.5.3         # Data processing
numpy==1.24.3         # Numerical computing
scikit-learn==1.3.0   # Machine learning
scapy==2.5.0          # Packet processing
```

---

## 🔄 DATA FLOW DIAGRAM

```
Input: PCAP File (network packets)
   ↓
[Packet Capture Module]
   ↓ (captures 100 packets)
data/traffic.pcapng
   ↓
[Feature Extraction Module]
   ↓ (parses packets)
data/features.csv
   ↓
[Sensitivity Engine Module]
   ↓ (applies ML model)
data/results.csv
   ↓
Output: Classification results with sensitivity levels
```

---

## ✅ VERIFICATION STEPS

### After Installation
```bash
# 1. Start server
python3 app.py &

# 2. Check diagnostics
curl http://localhost:5000/diagnostics
# Should show all true

# 3. Run full pipeline
curl http://localhost:5000/start-pipeline

# 4. Monitor status
curl http://localhost:5000/status
# Wait until progress reaches 100

# 5. Check results
curl http://localhost:5000/results

# 6. Verify output files
ls -lh data/
# Should have: traffic.pcapng, features.csv, results.csv
```

---

## 🆘 MISSING COMPONENT: sensitivity_model.pkl

**CRITICAL**: This file must exist for the pipeline to work!

```bash
# Check if you have it
ls -la sensitivity_model.pkl

# If missing:
# 1. Ask for the model file from your team
# 2. Copy it to project root: cp /path/to/model.pkl sensitivity_model.pkl
# 3. Verify it loads: python3 -c "import pickle; pickle.load(open('sensitivity_model.pkl', 'rb')); print('Model OK')"
```

**Model File Requirements**:
- Filename: `sensitivity_model.pkl`
- Format: Python pickle file
- Contents: Dict with keys: 'model', 'label_encoder', 'feature_names', 'classes'
- Size: Typically 5-20 MB

---

## 📞 TROUBLESHOOTING BY FILE

### Problems with app.py?
→ See **SETUP_AND_TROUBLESHOOTING.md** Section: "Flask port already in use"

### Problems with packet_capture.py?
→ See **SETUP_AND_TROUBLESHOOTING.md** Section: "No packets captured"

### Problems with feature_extraction.py?
→ See **SETUP_AND_TROUBLESHOOTING.md** Section: "Scapy error"

### Problems with sensitivity_engine.py?
→ See **SETUP_AND_TROUBLESHOOTING.md** Section: "Model not found"

### Problems with status updates?
→ See **SETUP_AND_TROUBLESHOOTING.md** Section: "JSON decode error"

### Can't figure it out?
→ Read **ISSUES_FOUND_AND_FIXED.md** to understand what was broken and how it was fixed

---

## 🚀 QUICK START (No Reading)

```bash
# Copy files to your project
cp /path/to/fixed/files/*.py .
cp /path/to/fixed/requirements.txt .
cp /path/to/sensitivity_model.pkl .

# Install
pip install -r requirements.txt
sudo apt-get install -y mininet openvswitch-switch tshark
echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/mn, /usr/bin/python3, /usr/sbin/tshark, /usr/bin/tshark, /bin/cp, /bin/rm, /usr/bin/chown, /usr/bin/chmod" | sudo tee -a /etc/sudoers.d/pipeline

# Run
python3 app.py

# In another terminal:
curl http://localhost:5000/start-pipeline
sleep 60
curl http://localhost:5000/results
```

---

## 📝 FILE SIZES (Approximate)

| File | Size | Notes |
|------|------|-------|
| app.py | 12 KB | Main Flask server |
| packet_capture.py | 8 KB | Mininet capture |
| feature_extraction.py | 6 KB | Feature extraction |
| sensitivity_engine.py | 20 KB | ML model + scoring |
| main_controller.py | 3 KB | Pipeline control |
| status_manager.py | 4 KB | Status tracking |
| sensitivity_model.pkl | 5-20 MB | **MUST PROVIDE** |
| requirements.txt | 0.1 KB | Dependencies |
| **Total Python Code** | **~53 KB** | Very lightweight! |

---

## 🎓 LEARNING RESOURCES

If you want to understand the code better:

1. **Flask & Web**: https://flask.palletsprojects.com/
2. **Mininet**: http://mininet.org/
3. **Scapy**: https://scapy.readthedocs.io/
4. **Pandas**: https://pandas.pydata.org/
5. **Scikit-Learn**: https://scikit-learn.org/

---

## ✨ SUMMARY

- ✅ **6 core Python files**: All fixed and ready to use
- ✅ **3 documentation files**: Comprehensive guides included
- ✅ **1 requirements file**: All dependencies listed
- ✅ **Thread-safe**: Multiple concurrent requests supported
- ✅ **Error handling**: Graceful failures with helpful messages
- ✅ **Diagnostics**: Built-in health checks
- ✅ **Logging**: Detailed debug information

**Everything you need is provided. You just need `sensitivity_model.pkl`!**
