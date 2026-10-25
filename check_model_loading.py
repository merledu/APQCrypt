"""Run this from the project folder:   python check_model_loading.py
It tells you whether the compact model is really being used by your sensitivity engine."""
import os, sys, time, warnings
warnings.filterwarnings("ignore")
import psutil

import sensitivity_engine as se

model_path = se.MODEL_PATH
lite = os.path.join(os.path.dirname(os.path.abspath(model_path)), "sensitivity_model_lite.npz")
print("Model file (pickle) :", model_path, "->", "found" if os.path.exists(model_path) else "NOT FOUND")
print("Compact file (.npz) :", lite, "->", "found" if os.path.exists(lite) else "NOT FOUND")

t0 = time.perf_counter()
m = se.get_cached_model(model_path)
load_ms = (time.perf_counter() - t0) * 1000
loader = getattr(m, "loader", None)
print("Loaded with         :", loader or "unknown (this engine has no 'loader' attribute)")
print("scikit-learn loaded :", "sklearn" in sys.modules)
print("Load time           : %.0f ms" % load_ms)
print("Memory of this process: %.0f MB" % (psutil.Process().memory_info().rss / 1e6))
print()
if loader and loader.startswith("compact"):
    print("RESULT: GOOD. The compact model is in use.")
elif not os.path.exists(lite):
    print("RESULT: the compact file does not exist yet.")
    print("  Fix: python compact_model.py convert sensitivity_model.pkl")
    print("  Then run this check again.")
elif not loader:
    print("RESULT: the compact file exists but your sensitivity_engine.py cannot use it.")
    print("  Fix: replace the RiskModel class with the one in use_only_if_check_fails/sensitivity_engine.py")
else:
    print("RESULT: the compact file exists but the engine still loaded the pickle.")
    print("  Check that sensitivity_model_lite.npz is in the SAME folder as sensitivity_model.pkl,")
    print("  and that compact_model.py is in the project folder.")
