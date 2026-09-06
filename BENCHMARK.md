# DGA Detection Benchmark

A larger, harder, **family-stratified** evaluation of the DNSentinel detector —
built to stress-test generalization beyond the small bundled training set and to
expose where the model actually struggles. Every number here is produced by
`backend/benchmarks/run_benchmark.py` and is fully reproducible (seeded).

```bash
python -m backend.benchmarks.generate_benchmark   # writes data/dga_benchmark.csv (seed=1337)
python -m backend.benchmarks.run_benchmark
```

## The benchmark

12,000 domains, balanced 6,000 malicious / 6,000 benign. Malicious domains are
generated from four published **DGA family patterns**; benign domains are real
English-word domains plus well-known real domains.

| Class | Family | n | Character of the domains |
|---|---|---|---|
| Malicious | `random` | 1,500 | uniform `[a-z0-9]` (Conficker / ramnit / cryptolocker class) |
| Malicious | `arithmetic` | 1,500 | LCG-seeded character selection (arithmetic DGA class) |
| Malicious | `hex` | 1,500 | long hex labels (base16 tunneling / exfil subdomains) |
| Malicious | `dictionary` | 1,500 | concatenated real words (suppobox / matsnu / gozi class) |
| Benign | `benign` | 6,000 | real English-word domains + known real domains |

> **Honesty note.** This set is *generated from published DGA patterns*, not
> scraped from a single named corpus, so it needs no external download and is
> reproducible anywhere. The harness also accepts real external CSVs — point
> `--benchmark` / `--train` at **CIC-Bell-DNS-EXF-2021**, **Tranco**, or
> **Bambenek** feeds to run the identical evaluation on recognized public data.

## Results (measured)

### 1. Cross-domain generalization — the number that matters
Model trained on the project's bundled data (`data/dns_exfiltration_dataset.csv`,
n=700), tested on all 12,000 benchmark domains it has never seen:

| Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| 0.761 | 0.698 | 0.918 | 0.793 | 0.918 |

Confusion `[[TN,FP],[FN,TP]] = [[3622, 2378], [491, 5509]]`.

### 2. Per-family recall — where it wins and where it struggles

| DGA family | Recall |
|---|---|
| random | **1.000** |
| arithmetic | **1.000** |
| hex | **1.000** |
| **dictionary** | **0.673** |
| **benign false-positive rate** | **0.396** |

Two honest takeaways a reviewer should see:
- The detector catches high-entropy DGAs (random / arithmetic / hex) essentially
  perfectly, but only **67%** of **dictionary DGAs** — the well-known hard case,
  because word-like malicious domains look structurally similar to benign ones.
- Trained only on the tiny bundled set, it **over-flags benign domains (39.6% FP)** —
  a direct consequence of unrepresentative training data, not model design.

### 3. In-benchmark ceiling — the fix is better training data
Stratified 80/20 split, trained **and** tested on the benchmark distribution:

| Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| 0.895 | 0.956 | 0.828 | 0.887 | 0.941 |

Confusion `[[TN,FP],[FN,TP]] = [[1154, 46], [206, 994]]`.

When the model is trained on representative data, **precision rises to 0.956 and
the benign false-positive rate collapses from 39.6% to ~3.8%.** This confirms the
cross-domain weakness is a *training-data coverage* problem — the roadmap fix is
to train on a larger, more representative benign+DGA corpus (e.g. Tranco + a DGA
feed), not to change the model.

## What this demonstrates
- The model's discriminative power is real for entropy-based DGAs (AUC 0.92 even
  cross-domain).
- Dictionary DGAs and benign false positives are the honest frontier — quantified
  per family rather than hidden behind a single headline accuracy.
- A clear, data-driven path to improvement, with the harness already able to
  consume recognized public datasets.
## Running on real public data

The harness accepts recognized public datasets — download them (no account
needed for most), convert to the `domain,label[,family]` format with the bundled
converter, and run. Sources:

- **Benign:** Tranco — <https://tranco-list.eu/top-1m.csv.zip> (`rank,domain`).
- **DGA (+benign, single file):** `chrmor/DGA_domains_dataset` on GitHub — a labeled
  CSV of 25 DGA families + Alexa benign.
- **DGA feeds:** Netlab 360 `dga.txt`, Bambenek `dga-feed.txt`.

```bash
# Option A — a combined labeled CSV (e.g. chrmor: columns domain,class,subclass)
python -m backend.benchmarks.build_public_benchmark \
    --input dga_domains_full.csv --domain-col domain \
    --label-col class --benign-value legit --family-col subclass
python -m backend.benchmarks.run_benchmark --benchmark data/real_benchmark.csv

# Option B — Tranco benign + a DGA .txt feed
python -m backend.benchmarks.build_public_benchmark \
    --benign-file top-1m.csv --malicious-file dga.txt --max 20000
python -m backend.benchmarks.run_benchmark --benchmark data/real_benchmark.csv
```

`run_benchmark` reports per-family recall for whatever families appear in the
data, so on the real feeds you get recall broken out by actual DGA family
(cryptolocker, ramnit, suppobox, matsnu, ...).

## Results on real public data (Netlab 360 / chrmor, 25 DGA families)

Trained on the bundled data, evaluated on 50,000 real domains (25,000 Alexa benign +
25,000 DGA across 25 families from the Netlab 360 Opendata Project, via
chrmor/DGA_domains_dataset). Reproduce with `tools/run_real_benchmark.py`.

**Cross-domain (bundled model -> real public data):**

| Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | --- | --- | --- | --- |
| 0.625 | 0.604 | 0.725 | 0.659 | 0.741 |

**In-benchmark (stratified 80/20 on the real data):**

| Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | --- | --- | --- | --- |
| 0.859 | 0.888 | 0.821 | 0.853 | 0.931 |

**Per-family recall (cross-domain) - real strengths and blind spots:**

- Caught (recall = 1.00): corebot, cryptolocker, emotet, gozi, matsnu, murofet, padcrypt, qadars, ramdo, ranbyus, rovnix, tinba
- Partial: symmi 0.97, nymaim 0.83, dircrypt 0.77, ramnit 0.76, necurs 0.71, suppobox 0.67, kraken 0.51, pykspa 0.50
- Missed: vawtrak 0.22, conficker 0.09, fobber 0.01, simda 0.01, pushdo 0.00

The consistent misses (conficker, fobber, simda, pushdo, vawtrak) generate short and/or
low-entropy, pronounceable domains that resemble benign structure, so entropy and n-gram
features alone cannot separate them. This is the concrete case for adding a character-level
sequence model and per-family thresholds - the documented next step.
