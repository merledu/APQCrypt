#!/usr/bin/env python3
"""
Compact Random Forest: runs the SAME trained forest with numpy only (no scikit-learn at run time).

Why: loading scikit-learn and the pickled forest costs seconds and many MB of memory in every process.
The compact form stores just the tree arrays. The predictions are the same (checked below).

  python compact_model.py convert sensitivity_model.pkl            -> sensitivity_model_lite.npz
  python compact_model.py convert sensitivity_model.pkl --max-trees 50     (optional: a smaller forest; accuracy is reported)
  python compact_model.py check   sensitivity_model.pkl            -> compares predictions with the original

Run "convert" ONCE on a computer that has scikit-learn and your pickle, then copy sensitivity_model_lite.npz next to
sensitivity_model.pkl on every machine (for example the RISC-V board). The app uses the compact file automatically.
"""
import argparse
import os
import pickle
import sys
import time

import numpy as np

LITE_NAME = "sensitivity_model_lite.npz"


class CompactForest:
    """Drop-in for the parts of RandomForestClassifier that we use: predict_proba, predict, n_estimators."""

    def __init__(self, left, right, feature, threshold, value, roots, model_classes, max_depth):
        self.left, self.right, self.feature, self.threshold = left, right, feature, threshold
        self.value, self.roots, self.classes_, self.max_depth = value, roots, model_classes, max_depth
        self.n_estimators = int(len(roots))

    def predict_proba(self, X, chunk=4000):
        X32 = np.asarray(X, dtype=np.float32)               # scikit-learn also compares in float32
        n = X32.shape[0]
        T, C = len(self.roots), self.value.shape[1]
        out = np.zeros((n, C), dtype=np.float64)
        for s in range(0, n, chunk):
            xs = X32[s:s + chunk]
            m = xs.shape[0]
            node = np.repeat(self.roots, m).astype(np.int64)
            row = np.tile(np.arange(m), T)
            for _ in range(self.max_depth + 2):
                l = self.left[node]
                internal = l >= 0
                if not internal.any():
                    break
                f = np.where(internal, self.feature[node], 0)
                go_left = xs[row, f] <= self.threshold[node]
                node = np.where(internal, np.where(go_left, l, self.right[node]), node)
            out[s:s + m] = self.value[node].reshape(T, m, C).mean(axis=0)
        return out

    def predict(self, X):
        return self.classes_[np.argmax(self.predict_proba(X), axis=1)]

    # ---- file format ----
    def save(self, path, feature_names, label_classes):
        np.savez(path, left=self.left, right=self.right, feature=self.feature, threshold=self.threshold,
                            value=self.value, roots=self.roots, model_classes=self.classes_, max_depth=self.max_depth,
                            feature_names=np.array(feature_names), label_classes=np.array(label_classes))

    @classmethod
    def load(cls, path):
        z = np.load(path, allow_pickle=False)
        cf = cls(z["left"], z["right"], z["feature"], z["threshold"], z["value"], z["roots"], z["model_classes"], int(z["max_depth"]))
        return cf, [str(x) for x in z["feature_names"]], [str(x) for x in z["label_classes"]]


class CompactLabels:
    """Replaces the scikit-learn LabelEncoder (only inverse_transform is needed)."""

    def __init__(self, classes):
        self.classes_ = np.array(classes, dtype=object)

    def inverse_transform(self, enc):
        return self.classes_[np.asarray(enc, dtype=int)]


def convert(pkl_path, out_path=None, max_trees=None):
    with open(pkl_path, "rb") as f:
        bundle = pickle.load(f)
    rf, le = bundle["model"], bundle["label_encoder"]
    trees = rf.estimators_[:max_trees] if max_trees else rf.estimators_
    left, right, feat, thr, val, roots, depth = [], [], [], [], [], [], 0
    off = 0
    for est in trees:
        t = est.tree_
        n = t.node_count
        l, r = t.children_left.astype(np.int64), t.children_right.astype(np.int64)
        left.append(np.where(l >= 0, l + off, -1))
        right.append(np.where(r >= 0, r + off, -1))
        feat.append(np.where(l >= 0, t.feature, 0))
        thr.append(t.threshold.astype(np.float64))
        v = t.value[:, 0, :].astype(np.float64)
        val.append((v / v.sum(axis=1, keepdims=True)).astype(np.float32))      # leaf class fractions
        roots.append(off)
        depth = max(depth, int(t.max_depth))
        off += n
    cf = CompactForest(np.concatenate(left).astype(np.int32), np.concatenate(right).astype(np.int32), np.concatenate(feat).astype(np.int16),
                       np.concatenate(thr), np.concatenate(val), np.array(roots, dtype=np.int64), np.asarray(rf.classes_), depth)
    out_path = out_path or os.path.join(os.path.dirname(os.path.abspath(pkl_path)), LITE_NAME)
    cf.save(out_path, bundle["feature_names"], list(le.classes_))
    return out_path, cf, bundle


def check(pkl_path, lite_path=None, rows=3000, seed=0, informational=False):
    lite_path = lite_path or os.path.join(os.path.dirname(os.path.abspath(pkl_path)), LITE_NAME)
    with open(pkl_path, "rb") as f:
        bundle = pickle.load(f)
    rf, le = bundle["model"], bundle["label_encoder"]
    cf, _, _ = CompactForest.load(lite_path)
    rng = np.random.default_rng(seed)
    nfeat = len(bundle["feature_names"])
    # test on random rows AND (if available) on the real packet features
    X = rng.random((rows, nfeat)) * rng.choice([1, 100, 10000], size=nfeat)
    sets = {"random rows": X}
    try:
        import pandas as pd
        import sensitivity_engine as se
        if os.path.exists("data/features.csv"):
            fe, *_ = se._build_feature_matrix(pd.read_csv("data/features.csv"))
            sets["your real packet features"] = fe.reindex(columns=bundle["feature_names"], fill_value=0.0).to_numpy(dtype=float)
    except Exception:
        pass
    ok = True
    for name, A in sets.items():
        t0 = time.perf_counter(); p_ref = rf.predict_proba(A); t_ref = time.perf_counter() - t0
        t0 = time.perf_counter(); p_new = cf.predict_proba(A); t_new = time.perf_counter() - t0
        agree = float((np.argmax(p_ref, 1) == np.argmax(p_new, 1)).mean())
        same = agree == 1.0
        diff = float(np.abs(p_ref - p_new).max())
        if informational:
            print(f"  {name}: {len(A)} rows | the smaller forest gives the same class as the full forest on {agree * 100:.1f}% of rows")
        else:
            print(f"  {name}: {len(A)} rows | same class on every row: {same} | largest probability difference: {diff:.2e} | scikit-learn {t_ref*1000:.0f} ms, compact {t_new*1000:.0f} ms")
            ok = ok and same and diff < 1e-5
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["convert", "check"])
    ap.add_argument("pkl")
    ap.add_argument("--max-trees", type=int, default=None)
    a = ap.parse_args()
    if a.cmd == "convert":
        out, cf, b = convert(a.pkl, max_trees=a.max_trees)
        print(f"wrote {out}: {cf.n_estimators} trees, {len(cf.left)} nodes, {os.path.getsize(out) / 1e6:.2f} MB "
              f"(original pickle {os.path.getsize(a.pkl) / 1e6:.2f} MB)")
        if a.max_trees:
            print("this is a SMALLER forest, so it is not identical to the original. Agreement with the full forest:")
            check(a.pkl, out, informational=True)
            print("RESULT: smaller forest written. Use it only if you accept the agreement above (and re-check your own accuracy).")
        else:
            print("checking against the original...")
            print("RESULT:", "OK, same predictions" if check(a.pkl, out) else "DIFFERENT (do not use; send me this output)")
    else:
        print("RESULT:", "OK, same predictions" if check(a.pkl) else "DIFFERENT")
