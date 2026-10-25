# Merge notes: APQCrypt-RUNNING + APQCrypt-time-fix

Applied on top of APQCrypt-RUNNING:
- sensitivity_engine.py : RiskModel now loads sensitivity_model_lite.npz (numpy only) automatically,
                          falls back to the pickle; predict_proba walked once instead of twice.
- compact_model.py      : same file in both zips (no change).
- templates/compare.html: stray ``` lines removed, numbers table id fixed (numTable), "Delete all stored runs"
                          button restricted to super_admin.
- check_model_loading.py: new, run it to confirm the compact model is in use.
- sensitivity_model_lite.npz: GENERATED (2.7 MB), identical predictions to the pickle (verified).

Measured here (fresh process):            pickle      compact
  model load time                         840 ms      74 ms
  process memory                          214 MB      79 MB
  scikit-learn imported                   yes         no

To use: unzip, activate your venv, run the app. Then on the Comparison page press
"Delete all stored runs" (super admin) and Measure all three again, because old runs were
measured before the fix. The adaptive card should say: AI model loaded with: compact (numpy, no scikit-learn).
Set APQ_NO_COMPACT=1 to force the old pickle path for A/B testing.

## Round 2: making adaptive cheaper (all outputs unchanged)
- sensitivity_engine.py : the forest runs only on DISTINCT feature rows (256 of 1000 here); results are
                          byte-identical to before (verified by file hash).
- compact_model.py      : .npz stored uncompressed -> loads in ~13 ms instead of ~70 ms. Re-run
                          `python compact_model.py convert sensitivity_model.pkl` if you retrain the model.
- policy_engine.py      : prefetch_resource_status(): the 0.5 s CPU reading (5 x 0.1 s waiting) now runs in the
                          background while features are extracted and scored, instead of after them.
- main_controller.py / service.py / comparison_worker.py: start that background reading for adaptive runs.
Measured (fresh process, mean of 5, this sandbox): wall 2.68 s -> 1.43 s, CPU 2.13 s -> 1.22 s,
memory 275 MB -> 151 MB, model load 0.92 s -> 0.013 s.
