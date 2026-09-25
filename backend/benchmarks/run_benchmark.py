"""Evaluate the DNSentinel detector on the family-stratified benchmark.

Reports three honest views:
  1. CROSS-DOMAIN   : train on the project's bundled data, test on the benchmark
                      (the realistic "does it generalize?" number).
  2. IN-BENCHMARK   : stratified 80/20 split trained AND tested on the benchmark
                      (ceiling when the model has seen this distribution).
  3. PER-FAMILY     : recall for each DGA family + benign false-positive rate
                      (shows dictionary DGAs are the hard case).

Point --benchmark / --train at real CSVs (CIC-Bell-DNS-EXF-2021, Tranco, Bambenek)
to run the same evaluation on recognized public data.
"""
from __future__ import annotations
import argparse, csv, os, sys
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                 # for generate_benchmark
sys.path.insert(0, os.path.join(_HERE, ".."))  # for features
from features import vectorize  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.metrics import (accuracy_score, precision_score, recall_score,  # noqa: E402
                             f1_score, roc_auc_score, confusion_matrix)

vec = vectorize

def load(path, dom="domain", lab="label", fam="family"):
    X, y, fams = [], [], []
    with open(path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            q = (row.get(dom) or "").strip()
            if not q: continue
            X.append(vec(q)); y.append(int(row[lab])); fams.append(row.get(fam, ""))
    return np.array(X, float), np.array(y, int), np.array(fams)

def rf(): return RandomForestClassifier(n_estimators=300, max_depth=30, min_samples_split=10, random_state=42)

def report(tag, yt, yp, pr=None):
    auc = f" auc={roc_auc_score(yt, pr):.3f}" if pr is not None and len(set(yt))==2 else ""
    print(f"{tag:<26} acc={accuracy_score(yt,yp):.3f} prec={precision_score(yt,yp,zero_division=0):.3f} "
          f"rec={recall_score(yt,yp,zero_division=0):.3f} f1={f1_score(yt,yp,zero_division=0):.3f}{auc}")
    print(f"{'':<26} confusion [[TN,FP],[FN,TP]] = {confusion_matrix(yt,yp).tolist()}")

def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--benchmark", default=os.path.join(here, "..", "..", "data", "dga_benchmark.csv"))
    ap.add_argument("--train", default=os.path.join(here, "..", "..", "data", "dns_exfiltration_dataset.csv"))
    a = ap.parse_args()

    if not os.path.exists(a.benchmark):
        print("[*] benchmark not found — generating it (seed=1337)...")
        from generate_benchmark import main as _gen
        import sys as _sys
        _argv = _sys.argv
        _sys.argv = ["generate_benchmark", "--out", a.benchmark]
        try:
            _gen()
        finally:
            _sys.argv = _argv

    Xb, yb, fam = load(a.benchmark)
    print(f"benchmark: {len(yb)} rows  (malicious={int(yb.sum())}, benign={int((yb==0).sum())})\n")

    # 1. CROSS-DOMAIN: train on the project's bundled data, test on the whole benchmark.
    Xtr, ytr, _ = load(a.train)
    clf = rf().fit(Xtr, ytr)
    yp = clf.predict(Xb); pr = clf.predict_proba(Xb)[:, 1]
    report("CROSS-DOMAIN (bundled->bench)", yb, yp, pr)

    # 3. PER-FAMILY recall under the cross-domain model + benign FP rate.
    print("\nper-family recall (cross-domain model):")
    mal_families = sorted(set(fam[yb == 1]))
    for f in mal_families:
        m = (fam == f) & (yb == 1)
        if m.sum():
            print(f"  {str(f):<14} recall={recall_score(yb[m], yp[m], zero_division=0):.3f}  (n={int(m.sum())})")
    bm = fam == "benign"
    if bm.sum():
        fp = (yp[bm] == 1).mean()
        print(f"  benign FP-rate={fp:.3f}  (n={int(bm.sum())})")

    # 2. IN-BENCHMARK ceiling: stratified split trained + tested on the benchmark.
    Xtr2, Xte2, ytr2, yte2 = train_test_split(Xb, yb, test_size=0.2, stratify=yb, random_state=42)
    clf2 = rf().fit(Xtr2, ytr2)
    yp2 = clf2.predict(Xte2); pr2 = clf2.predict_proba(Xte2)[:, 1]
    print()
    report("IN-BENCHMARK (80/20 split)", yte2, yp2, pr2)

if __name__ == "__main__":
    main()
