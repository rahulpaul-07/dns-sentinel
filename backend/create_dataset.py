"""Generate the small synthetic DGA dataset used by the DL scorer (train_dga.py).

This is a *toy* corpus: benign names are brand + number combinations and the
malicious class is uniformly random alphanumerics. It exists so the optional
character-level model can be trained end to end without downloading anything.
For honest numbers use the family-stratified benchmark in benchmarks/.

    python backend/create_dataset.py            # writes backend/dga_dataset_generated.csv

The committed backend/dga_dataset.csv is the frozen copy the evaluation and
drift tests are pinned to; this script writes to a separate file by default so
regenerating never silently changes published numbers.
"""
import argparse
import os
import random
import string

import pandas as pd

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(BACKEND_DIR, "dga_dataset_generated.csv")


def generate_benign(rng: random.Random, n: int = 500):
    prefixes = ["google", "github", "microsoft", "apple", "amazon", "netflix", "facebook",
                "twitter", "linkedin", "reddit", "stackoverflow", "wikipedia", "medium",
                "spotify", "adobe", "dropbox", "slack", "zoom", "discord", "twitch"]
    suffixes = ["com", "net", "org", "io", "dev", "ai", "co"]
    subdirs = ["", "api.", "mail.", "dev.", "static.", "cdn.", "assets."]
    return [
        rng.choice(subdirs) + rng.choice(prefixes) + str(rng.randint(1, 99)) + "." + rng.choice(suffixes)
        for _ in range(n)
    ]


def generate_dga(rng: random.Random, n: int = 500):
    chars = string.ascii_lowercase + string.digits
    suffixes = ["com", "net", "org", "ru", "cn", "top", "xyz", "bit"]
    return [
        "".join(rng.choice(chars) for _ in range(rng.randint(15, 30))) + "." + rng.choice(suffixes)
        for _ in range(n)
    ]


def create_dataset(out_path: str = DEFAULT_OUT, n_per_class: int = 500, seed: int = 42) -> str:
    rng = random.Random(seed)
    benign = generate_benign(rng, n_per_class)
    dga = generate_dga(rng, n_per_class)
    df = pd.DataFrame({"domain": benign + dga, "label": [0] * len(benign) + [1] * len(dga)})
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    df.to_csv(out_path, index=False)
    print(f"[*] Dataset created: {out_path} ({len(df)} samples, seed={seed})")
    return out_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--n", type=int, default=500, help="samples per class")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    create_dataset(a.out, a.n, a.seed)
