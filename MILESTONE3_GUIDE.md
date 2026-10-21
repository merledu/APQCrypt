# APQCrypt Milestone 3: the three interfaces (step by step)

The rubric asks for a live demo with **all functionalities** plus three clearly shown interfaces. They are now built into the app as three new pages:

| Rubric item | Page in the app | What it is |
|---|---|---|
| **Debugging interface** (for processing steps) | **6 · Debug** (`/debug`) | Look inside every step: run to a step, re-run from a step, inspect settings, results and log lines, trace one conversation through all 8 stages, live log, downloadable debug bundle |
| **Wrapper interface** (for external interfaces) | **7 · Interfaces** (`/interfaces`) + the REST API `/api/v1` + `apqcrypt_client.py` | Adapters around the external parts (packet source, AI model file, ML-KEM library) with status, test, and switching. A documented API with a key that other programs can call, an API explorer, and a Python client / command-line tool |
| **Configuration interface** (for customizations) | **8 · Settings** (`/settings`) | Edit scoring, port scores, decision table, limits, presets, capture size. Every value is checked. Save, reset, import, export. A copy of the settings is saved with each run |

Your five earlier pages (Capture, Sensitivity, System condition, Encryption, Compare) stay as they are.

---

## Step 1: Put the files in your project (15 min)

Copy everything in this folder over your project folder (the same way as the last package).

```
APQCrypt/
├── app.py                  ← REPLACE
├── main_controller.py      ← REPLACE
├── feature_extraction.py   ← REPLACE
├── sensitivity_engine.py   ← REPLACE
├── policy_engine.py        ← REPLACE
├── encryption_engine.py    ← REPLACE
├── comparison.py           ← NEW   (comparison engine: measured runs + evidence)
├── comparison_worker.py    ← NEW   (one measured run per fresh process; algorithm costs)
├── config.py               ← NEW   (settings: defaults, checks, presets)
├── debuglog.py             ← NEW   (step log used by the Debug page)
├── interfaces.py           ← NEW   (adapters: packet source, AI model, ML-KEM)
├── service.py              ← NEW   (one-run-at-a-time lock, API jobs)
├── api_v1.py               ← NEW   (REST API)
├── apqcrypt_client.py      ← NEW   (Python client + command line)
├── selftest.py             ← NEW   (checks everything in one command)
├── measure_latency.py      ← NEW   (real timing numbers for the speed question)
├── start.sh                ← NEW   (one-command start)
├── make_sample_pcap.py, compare_old_new.py   (from before)
├── packet_capture.py       ← EDIT BY HAND (see PACKET_CAPTURE_EDITS.md)
├── status_manager.py       ← KEEP
├── sensitivity_model.pkl   ← KEEP
├── requirements.txt        ← KEEP (no new packages needed)
├── templates/              ← base.html + 8 page files (3 are new: debug, interfaces, settings)
└── static/                 ← style.css, app.js, chart.umd.js (REPLACE)
```
Old files in `templates/` that are not in this package (like `index.html`) can be deleted.

## Step 2: Start it and run the self-test (10 min, on the Linux VM)

```
bash start.sh
```
Open **http://127.0.0.1:5000**. You should see 8 tabs. In a second terminal (same folder, venv active):

```
python selftest.py
```
It checks all 8 pages, the settings checks and presets, the connections and API, a pipeline run, and the debug data. At the end it prints `NN passed, 0 failed`.
If a line says `FAIL`, read the text next to it. The most common one is a missing ML-KEM library (see "If something breaks").

## Step 3: Edit packet_capture.py (40 min)

Follow **PACKET_CAPTURE_EDITS.md** (C1 to C4, and C6 so the Capture settings work). Then run one real capture from the app and open page 1 to check the packet count and protocol mix.

## Step 4: Learn the three interfaces (30 min)

**6 · Debug**
- **Processing steps table:** 5 steps with status, time, rows, output file. Press **Inspect** to see the settings the step used, its result numbers, its log lines, and a sample of its output file.
- **Run to a step / Re-run from a step:** for example run only up to step 3 and look at the scores, or change a setting and re-run from step 3 without capturing again.
- **Trace a conversation:** pick a conversation (for example the one with `SNI:bank...`) and press Trace. You see 8 cards: capture → features → rule score → AI risk → combine → policy → key exchange → encryption and checks, each with its values.
- **Live log:** every step writes events while it runs. Filter by step or level. **Debug bundle** downloads a zip with the settings, log and all result files.

**7 · Interfaces**
- **External connections:** packet source (Mininet + tshark, or a capture file), AI model, ML-KEM provider (real liboqs, or a simulated one for development that is labelled "NOT quantum-safe"). Each shows available/unavailable, has a **Test** button, and **Use this** switches the active one for the next run.
- **REST API explorer:** pick an endpoint, press Send, see the JSON reply and the same request as a `curl` command.
- **Python client:** `python apqcrypt_client.py decide --protocol HTTPS --port 443`.

**8 · Settings**
- Edit values, press **Save**. Wrong values are refused with a message. Try setting HIGH to `X25519`: it is refused (HIGH must stay quantum-safe).
- **Presets:** Balanced, IoT low power, High security.
- **Export / Import / Reset.**
- Changes apply to the **next run**, and the run's own copy is saved to `data/run_config.json` (shown on the Debug page).

## Step 4b: Get your real timing numbers (5 min, needed for the speed answer)

```
python measure_latency.py
```
It measures, without the capture step: the AI model the OLD way (one packet at a time) versus the NEW way (all at once), scoring cost per packet, key exchange cost (classical vs hybrid), encryption cost per packet, the estimated decision cost for a new conversation, and the end-to-end analysis speed. It saves `data/latency_report.json`. Put these numbers on your slides and in Section 5.3 of the Defence guide. Run it on the Linux VM, and again on the RISC-V board when it is ready.

## Step 5: Practise this demo (about 7 minutes)

| # | Do this | Say this |
|---|---|---|
| 1 | Open **Interfaces**. Point at the connections table. Press **Test** on ML-KEM. | "These are the external parts we depend on. Each is wrapped in an adapter, so we can swap one without changing the pipeline." |
| 2 | Switch the packet source to **Capture file**, then back. | "The same pipeline can read a live Mininet capture or an existing recording." |
| 3 | In the API explorer, send **GET /health**, then **POST /decide**. Show the `curl` line. | "Other tools can ask us which protection a conversation needs. This is the wrapper for outside programs." |
| 4 | In a terminal: `python apqcrypt_client.py decide --protocol SSH --port 22` | "Same API from a separate program, with a Python client." |
| 5 | Open **Settings**. Pick the **High security** preset, **Save**. Then try to set HIGH to X25519: show the refusal. | "Every customization is in one place and checked. HIGH cannot be made unsafe by accident." |
| 6 | Press **Start pipeline** (live Mininet capture if your VM works, otherwise tick *Reuse last capture*). Watch the progress bar. | "All stages run: capture, features, scoring, policy, encryption." |
| 7 | Open **Debug**. **Inspect** the Sensitivity step. Show its settings (they match what you saved). | "Each step shows its input, settings, and output." |
| 8 | Select the bank-name conversation, press **Trace it**. Read the 8 cards. | "Here is one conversation through the whole system: the website name, the rule score, the AI score, the combined level, the policy, the key exchange, the encryption and the checks." |
| 9 | Pick **Run up to step 3**, press it. Then change one setting and **Re-run from step 3**. | "We can stop at any step and re-run from it for debugging." |
| 10 | Open **Comparison**. Show the Test setup (machine, capture fingerprint), then the charts and the numbers table. Press **⬇ evidence (.csv)**. (Measure all three before the demo; do not measure live.) | "Every bar is a real measured run on this machine with the same capture. Here is the evidence file." |

## Step 6: Schedule (Friday to Monday)

| Day | Do |
|---|---|
| **Friday (today)** | Steps 1 and 2. Get `selftest.py` fully green on the Linux VM. Install real liboqs. Do the `packet_capture.py` edits and one real capture |
| **Saturday** | Run the full pipeline and the comparison with real data. Practise the demo (Step 5) twice. **Record a screen video of the whole demo as a backup.** Commit: `git add -A && git commit -m "milestone 3"` |
| **Sunday** | Dry run on the exact computer you will present on. Fix only small things. Prepare answers (see the Defence report). Stop changing code in the evening |
| **Monday** | Arrive early. Start the app. Run `python selftest.py` and keep the output. Run the pipeline once and the comparison once before the panel arrives |

## "Separate IDE": what to do

The rubric wording is not clear. This package gives you a **standalone application** (`bash start.sh`, its own interface with the debug, wrapper and configuration parts). Ask your supervisor one question to be sure: *"By 'demonstrated from separate IDE', do you mean running the project as its own standalone application, not by editing code in an editor?"* If they mean something else, tell me what they said and I will adjust.

## If something breaks

| Problem | Fix |
|---|---|
| `ML-KEM` chip is red / selftest says liboqs missing | liboqs is not built. On the VM: `pip install git+https://github.com/open-quantum-safe/liboqs-python.git` then `python -c "import oqs"` (the first import builds liboqs, it takes minutes). For a quick test only you may select the **simulated** provider on the Interfaces page. It is labelled NOT quantum-safe, so never use it for results or the panel |
| "No sudo access" when pressing Start | `echo "$USER ALL=(ALL) NOPASSWD:ALL" \| sudo tee /etc/sudoers.d/apqcrypt` (lab VM only), or tick **Reuse last capture** |
| Start says "'comparison' is already running" | Only one thing runs at a time. Wait for it to finish |
| Settings page says "Not saved" | Read the message. It names the field and the allowed range |
| Debug page is empty | Run the pipeline once. The log is cleared at the start of each full run |
| `python selftest.py` fails on a page | Run `python app.py` and read the terminal for the error |
| The API says 401 | Use the key in `data/api_key.txt` (the Interfaces page shows it with the Show button) |

## What was tested, and what was not

**Tested** (35 automatic checks in `selftest.py`, plus real-browser tests of every new page, using a synthetic capture and a stand-in for ML-KEM and for your Random Forest):
- All 8 pages open with no browser errors.
- Settings: wrong values refused, unsafe HIGH refused, presets, reset, deleted ports stay deleted, and the changes really change the pipeline (decision table, score limits, peek on/off, CPU limit).
- Interfaces: connections list, Test, switching the adapter, the API (key required, validation, uploads, jobs, CSV), the Python client.
- Debug: step table, Inspect, trace of 8 steps, live log with filters, run-to-step, re-run-from-step, debug bundle.

**Not tested (you must check on your machine):** real Mininet capture, real liboqs ML-KEM, your real model, the `packet_capture.py` edits, anything on the RISC-V board.

## Honest limits (say them if asked)
- The API listens on this computer only and needs a key. It is a prototype interface, not a production service.
- Both sides of the key exchange still run in one program. Authentication is future work.
- The simulated ML-KEM exists only so the app can be tested without liboqs. Its results are labelled and never counted as quantum-safe.
- The "Capture" settings only apply after edit C6 in `PACKET_CAPTURE_EDITS.md`.

## Update: the Comparison page was rebuilt as a Comparison Engine

Read **COMPARISON_ENGINE_GUIDE.md**. In short: each mode (normal, all quantum-safe, adaptive) is measured for real on demand, in its own process, on the same capture, and saved as evidence. A mode you did not measure has no bar. It also covers the RISC-V board (installation risks, time, memory) and which dropdowns to keep. `benchmark.py` is deleted. Add this to the step list: after Step 4b, open **5 · Comparison** and press **Measure all three** (Step 5 of the comparison guide), then **Measure algorithm costs**.
