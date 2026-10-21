# Comparison Engine: how it works, how to use it, and the RISC-V board

## 1. Short answers to your questions

**Does your idea make sense?** Yes, and it is the right fix. A bar should exist only for something that was really run, and the page must show how it was measured. That is how the page works now.

**What was wrong with the old Compare page?** One button ran all three modes on the recording, so the bars were measured, not invented. But there were three real problems:
1. **No evidence trail.** You could not show when, where, on which capture, or how many times each bar was measured.
2. **The memory chart was meaningless.** All three modes ran inside the same process, so memory looked the same for all of them.
3. **Adaptive looked cheaper than it is.** The old test started after the scoring step, so the AI model loading and scoring time of the adaptive mode was left out. The supervisor's speed objection is about exactly that cost, so it must be included.

**How it works now:**
- You press **Measure** on each mode (A Normal, B All quantum-safe, C Adaptive), or **Measure all three**.
- Each run is a **fresh process** that replays the **same capture** through that mode. Time, CPU and peak memory are read from that process.
- The first run of each mode is a **warm-up and is not counted**. You choose how many counted runs (1, 3, 5, 10).
- Every run is saved with its **evidence** (see section 3).
- **Modes you never measured have no bar.** The page says "Not measured yet".

**Should you keep the dropdowns?** Keep two, hide the rest (details in section 4).

**Will the all-quantum-safe mode be too heavy for the RISC-V board?** Memory: no. Time: probably fine, but only a measurement can tell, and the page includes a tool for it. Support: the real risks are installing the software, not running it. Section 5 covers this.

---

## 2. What each mode does in the engine

| Mode | What runs | What is counted |
|---|---|---|
| **A · Normal** | X25519 key exchange + AES-256-GCM for every conversation | read capture + key exchange + encryption |
| **B · All quantum-safe** | hybrid X25519 + ML-KEM-1024 for every conversation + AES-256-GCM | read capture + key exchange + encryption |
| **C · Adaptive** | AI model load + scoring + computer-condition reading + policy, then the key exchange and lock chosen per conversation | read capture + **decision** + key exchange + encryption |

The adaptive decision cost is shown separately in the chart "Where the time goes", so nothing is hidden.

**Important wording:** mode A is "normal encryption" as implemented in our engine (the same libraries and the same capture as the other two), not a live network tunnel. All three are measured in exactly the same way, which is what makes the comparison fair. Say it that way.

## 3. What is saved as evidence for every run
Time and date, which mode, whether it was a warm-up, **the machine** (board name, CPU, cores, RAM, OS, Python), **the capture fingerprint** (a short code of the file, its size, packet and conversation counts), the settings used (adaptive), total time, CPU time, peak memory, time per phase, key exchange time, encryption time, extra bytes, how many conversations were quantum-safe, and the decrypt and tamper self-check results.

**A run is not counted (but is stored and shown) if:**
- it used the **simulated** ML-KEM instead of real liboqs,
- its self-checks failed,
- mode B did not give every conversation a quantum-safe key exchange,
- or it failed.

**Results are never mixed** across machines or captures. If you measure on the PC and on the board, each machine has its own set. The page shows which one you are viewing.

Download everything with **⬇ evidence (.csv)**. That file is your proof: open it in Excel in front of the panel if asked.

## 4. The dropdowns

| Dropdown | What it does | Decision |
|---|---|---|
| **Policy mode** (Adaptive / Static AES / All quantum-safe) in the top bar | Chose which policy a single pipeline run uses | **Hidden on every page except Debug.** The Compare page now measures the baselines properly, so this was a duplicate that could silently change a pipeline run |
| **Computer load** (Real / Simulate free / Simulate busy) in the top bar | Changes the computer condition used by the adaptive policy in a pipeline run | **Kept** on the pipeline pages, because it is how you demonstrate adaptivity ("busy computer: HIGH still quantum-safe") |
| **Reuse last capture** | Skips the capture step | **Kept** (practical) |
| Compare page: **Runs per mode** | How many counted runs per mode (plus one warm-up) | Kept. Use 3 on the board, 5 on the PC |
| Compare page: **interleave runs** | Mixes the order A, B, C, A, B, C so slow changes in the computer affect all modes equally | Kept, ticked by default |
| Compare page, Adaptive card: **computer condition** | Real / simulate free / simulate busy for the adaptive measurement | **Kept.** It is saved with each run. If you measure adaptive under both free and busy, the page shows two adaptive bars (C free, C busy). That shows the adaptation with real numbers |

The top-bar options are hidden on the Compare page, because they do not apply there.

**Which adaptive condition should you measure?** Measure **free** for the main comparison. Then measure **busy** once as well, so the panel sees how the choice changes when the computer is under load.

## 5. The RISC-V board (from your screenshots)

**What the screenshots show:** SiFive HiFive Unmatched A00, riscv64, 4 cores, 15 GiB RAM (13 GiB free, no swap), a 29 GB SD card with 21 GB free, Ubuntu.

### 5.1 Will "all quantum-safe" be too heavy?
- **Memory: no.** ML-KEM uses only a few kilobytes. The process memory is dominated by Python, pandas and scapy (about 125 MB in my test on a PC), and the adaptive mode adds the AI model. You have 13 GiB free.
- **Time: probably fine, but measure.** Mode B does one hybrid key exchange **per conversation, not per packet**. Its cost is about (number of conversations) × (cost of one key exchange). On your capture that is on the order of 10 to 100 conversations, so it should be seconds, not minutes. I cannot give the board's number. Press **Measure algorithm costs** on the board first: it measures one X25519, one ML-KEM-768 and ML-KEM-1024 key generation, encapsulation and decapsulation, AES-GCM and ChaCha20-Poly1305 on the board itself.
- **Support: the algorithms are fine, the installation is the risk.** See below.

### 5.2 Real risks, in order, and what to do
1. **Python packages.** PyPI often has no ready-made riscv64 packages for numpy, pandas, scikit-learn and cryptography, so `pip` may try to compile them (very slow, can fail). **Use Ubuntu's own packages:**
   ```
   sudo apt update
   sudo apt install -y python3-venv python3-numpy python3-pandas python3-sklearn python3-cryptography python3-psutil python3-scapy python3-flask git cmake ninja-build build-essential libssl-dev
   python3 -m venv --system-site-packages venv
   source venv/bin/activate
   ```
   (`--system-site-packages` lets the venv use those apt packages. Check the packages exist for your Ubuntu version; if one is missing, tell me.)
2. **The saved AI model.** `sensitivity_model.pkl` was saved with the scikit-learn version on your PC. A different version on the board can warn or fail to load. Test early: `python -c "import pickle; pickle.load(open('sensitivity_model.pkl','rb')); print('model ok')"`. If it fails, re-save or retrain the model on the board (or use the same scikit-learn version).
3. **liboqs (ML-KEM).** It builds from source as plain C code on riscv64. It should work but without processor-specific speed-ups, and the build can take a long time on this board. Start it early, not on Monday morning:
   `pip install git+https://github.com/open-quantum-safe/liboqs-python.git` then `python -c "import oqs"` (the first import builds it).
4. **Mininet and Open vSwitch.** Check: `which mn`, and `sudo modprobe openvswitch` (it must not print an error). If the board cannot run Mininet, **record the capture on the PC and copy `data/traffic.pcapng` to the board.** The pipeline and the comparison only need the capture file. Tick "Reuse last capture". The page shows the capture fingerprint, so you can prove the PC and the board used the same file.
5. **A browser on the board.** One may not be available. Run `APQ_HOST=0.0.0.0 python app.py` on the board and open `http://<board-ip>:5000` from your laptop (lab network only).
6. **Waiting time.** Every run starts a fresh Python process, and loading pandas, scapy and scikit-learn can take tens of seconds on this board. That load time is **not** counted in the results, but you wait for it. Plan **15 to 30 minutes** for "3 runs per mode, all three modes". Start early.
7. **AES speed.** To my knowledge the U74 cores in this board do not have the RISC-V crypto instructions, so AES runs in software. Check with `grep isa /proc/cpuinfo` (look for letters starting `zk`). If AES is slow here, ChaCha20-Poly1305 may be faster, which would support your policy choice for busy computers. The micro-benchmark shows this with numbers. Do not claim it before you measure.

### 5.3 The safe plan (in order of preference)
1. **Everything on the board:** capture (or copy the capture), measure A, B, C and the algorithm costs. Report these as the board results.
2. **If the board cannot run Mininet:** capture on the PC, copy the file, measure on the board.
3. **If liboqs cannot be built on the board:** measure all three modes on the PC (the Linux VM), and say so. For the board, use the RISC-V benchmark report you already have for the algorithm costs and say clearly which numbers are from which machine. Never mix them into one chart.
4. **Always** keep the PC results as well. Both machines can be shown: the page lets you choose which machine's results you are viewing.

## 6. How to use it (step by step)

1. Make sure a capture exists (`data/traffic.pcapng`): run the pipeline once, or copy a capture in.
2. Open **5 · Comparison**. Check the **Test setup** panel: machine, capture fingerprint, ML-KEM provider (it must say `liboqs`, not simulated).
3. Set **Runs per mode** (3 or 5). Press **Measure all three**. Watch the progress bar. It takes a while.
4. Optional but recommended: in the Adaptive card choose **simulate: busy** and press **Measure Adaptive** to add the busy bar.
5. Press **Measure algorithm costs** once.
6. Read **What the measurements say** (written from the measured numbers), the charts, and the numbers table.
7. Press **⬇ evidence (.csv)** and keep the file with your results.
8. Take screenshots for the slides.

## 7. What to say to the panel
- "Every bar is a measurement. Each mode was run on the same capture, in its own process, N times after a warm-up. Here is the evidence file."
- "Adaptive costs more total time than the normal mode, because it adds the decision (loading the AI model, scoring, policy). That cost is shown separately. What it buys is that every HIGH conversation is quantum-safe, at a lower key-exchange cost than protecting everything."
  (Say this only if your own numbers show it. If they show something different, say what they show.)
- "This measures processing cost on this machine. It is not live network delay, and 'normal' means X25519 + AES-256-GCM in our engine, not a deployed tunnel."
- "Results from the PC and the RISC-V board are reported separately."

## 8. Files (what to copy into your project)

| File | Action |
|---|---|
| `comparison.py` | **NEW** (runs the measurements, stores the evidence, writes the findings) |
| `comparison_worker.py` | **NEW** (one measured run in its own process; also the algorithm micro-benchmark) |
| `app.py` | **REPLACE** (new comparison routes; the old benchmark routes are gone) |
| `encryption_engine.py` | **REPLACE** (small change so the worker does not overwrite the dashboard's check file) |
| `templates/compare.html` | **REPLACE** |
| `static/app.js`, `static/style.css` | **REPLACE** |
| `selftest.py` | **REPLACE** (now 56 checks, including the comparison engine) |
| `benchmark.py` | **DELETE** (replaced by the engine) |

Stored data lives in `data/comparison/runs.jsonl` and `data/comparison/micro.jsonl`.

## 9. What was tested and what was not

**Tested** (56 automatic checks in `selftest.py` and a real-browser test of the page):
- Nothing is shown before anything is measured. A mode that was not run has no data and no bar.
- Mode A really uses no quantum-safe keys, mode B uses them for every conversation, and adaptive pays a decision cost that is shown.
- Memory differs between modes because each run is its own process (adaptive includes the AI model).
- Warm-up runs are stored but not counted. Simulated ML-KEM and failed self-checks are not counted. Quantum-safe modes refuse to run without real liboqs.
- Results of other machines or captures are not mixed. Evidence CSV, micro-benchmark, clearing a mode, cancel, and the lock that stops the pipeline and a measurement from running together.

**Not tested (you must check):** real liboqs ML-KEM, your real model and capture, and the RISC-V board. I used a stand-in for ML-KEM and a small stand-in for the model, so the numbers I saw while testing mean nothing. Only your own runs count.
