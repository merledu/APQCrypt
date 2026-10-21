"""
Compare the OLD pipeline output with the NEW one on the same recording.

Usage:   python compare_old_new.py OLD_DATA_FOLDER NEW_DATA_FOLDER
Example: python compare_old_new.py ../APQCrypt_old/data data

It reads results.csv and policy.csv from both folders and prints:
  1. how many rows each has
  2. how the sensitivity levels changed (and which rows moved, if the row counts match)
  3. which algorithms were chosen
  4. how many locks can detect tampering (AEAD) before and after
  5. how many conversations got quantum-safe key exchange, and how many HIGH ones did
"""
import os
import sys
import pandas as pd

if len(sys.argv) != 3:
    print(__doc__)
    sys.exit(1)

old_dir, new_dir = sys.argv[1], sys.argv[2]


def load(folder, name):
    p = os.path.join(folder, name)
    return pd.read_csv(p) if os.path.exists(p) else None


def dist(df, col):
    if df is None or col not in df.columns:
        return None
    return {str(k): int(v) for k, v in df[col].value_counts().items()}


def is_aead(s):
    s = str(s).upper()
    return "GCM" in s or "POLY1305" in s


def pq_flag(df):
    if df is None or "PQC_Handshake_Used" not in df.columns:
        return None
    return df["PQC_Handshake_Used"].astype(str).str.lower().isin(["true", "1"])


def pct(a, b):
    return f"{a}/{b} ({round(100 * a / b)}%)" if b else "n/a"


def show(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


old_r, new_r = load(old_dir, "results.csv"), load(new_dir, "results.csv")
old_p, new_p = load(old_dir, "policy.csv"), load(new_dir, "policy.csv")

show("1. ROWS")
for label, o, n in [("results.csv", old_r, new_r), ("policy.csv", old_p, new_p)]:
    print(f"{label}: old={len(o) if o is not None else 'missing'}  new={len(n) if n is not None else 'missing'}")

show("2. SENSITIVITY LEVELS (per packet)")
print("OLD:", dist(old_r, "Sensitivity"))
print("NEW:", dist(new_r, "Sensitivity"))
if old_r is not None and new_r is not None and "Sensitivity" in old_r and "Sensitivity" in new_r:
    if len(old_r) == len(new_r):
        ct = pd.crosstab(old_r["Sensitivity"].rename("old"), new_r["Sensitivity"].rename("new"))
        print("\nRows by (old level -> new level):")
        print(ct.to_string())
        moved = int((old_r["Sensitivity"].values != new_r["Sensitivity"].values).sum())
        print(f"\nRows whose level changed: {pct(moved, len(old_r))}")
    else:
        print("\n(Row counts differ, so rows cannot be matched one by one. Use the same recording for both runs.)")

show("3. ALGORITHMS CHOSEN")
print("OLD:", dist(old_p, "Selected_Algorithm"))
print("NEW:", dist(new_p, "Selected_Algorithm"))

show("4. LOCKS THAT DETECT TAMPERING (AES-GCM / ChaCha20-Poly1305)")
for label, df in [("OLD", old_p), ("NEW", new_p)]:
    if df is not None and "Symmetric_Cipher" in df.columns:
        n = int(df["Symmetric_Cipher"].map(is_aead).sum())
        print(f"{label}: {pct(n, len(df))} of rows use a tamper-detecting lock")
        weak = df.loc[~df["Symmetric_Cipher"].map(is_aead), "Symmetric_Cipher"].value_counts().to_dict()
        if weak:
            print(f"      without tamper detection: {weak}")

show("5. QUANTUM-SAFE KEY EXCHANGE")
for label, df in [("OLD", old_p), ("NEW", new_p)]:
    flag = pq_flag(df)
    if flag is None:
        print(f"{label}: no PQC_Handshake_Used column")
        continue
    print(f"{label}: {pct(int(flag.sum()), len(df))} of rows are on a quantum-safe key exchange")
    if "Sensitivity" in df.columns:
        high = df["Sensitivity"] == "HIGH"
        print(f"      HIGH rows that are quantum-safe: {pct(int((flag & high).sum()), int(high.sum()))}")
        if "Resource_Status" in df.columns:
            busy = high & (df["Resource_Status"] == "CONSTRAINED")
            if busy.any():
                print(f"      HIGH rows when the computer was busy: {pct(int((flag & busy).sum()), int(busy.sum()))} quantum-safe")
print()
