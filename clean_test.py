"""One-shot clean evaluation of the Phase 1 detectors.

RULES: run this ONCE, after you have finished tuning, and do not tune afterwards.
If you change thresholds, rules or training data after seeing these results, this
test is "burned": write a fresh set before you report numbers again.

You must create two files first (one prompt per line, blank lines ignored):
  data/clean_attacks.txt        about 25 attacks, written in YOUR OWN words
  data/clean_benign_hard.txt    about 20-30 harmless prompts that sound suspicious

It also uses data the system never trained on:
  - the deepset/prompt-injections TEST split (training used only the train split)
  - 100 Dolly instructions that are not in models/train_texts.json
    (run train_classifier.py once after the one-line patch that saves that file)
"""
import json
import math
import random
from pathlib import Path

from datasets import load_dataset

from detectors.classifier_detector import ClassifierDetector
from detectors.keyword_detector import KeywordDetector
from detectors.similarity_detector import SimilarityDetector

DATA = Path("data")
TRAIN_TEXTS = Path("models/train_texts.json")


def read_lines(name: str) -> list[str]:
    path = DATA / name
    if not path.exists():
        raise SystemExit(f"Missing {path}. Create it first (see the instructions at the top of this file).")
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion k/n. Shows how little a small set can prove."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


# ------------------------------------------------------------------ #
# Build the five test sets
# ------------------------------------------------------------------ #
if not TRAIN_TEXTS.exists():
    raise SystemExit("Missing models/train_texts.json. Apply the one-line patch to "
                     "train_classifier.py, re-run it, then run this again.")
train_set = {t.strip().lower() for t in json.loads(TRAIN_TEXTS.read_text(encoding="utf-8"))}

my_attacks = read_lines("clean_attacks.txt")
my_benign = read_lines("clean_benign_hard.txt")

deepset_test = load_dataset("deepset/prompt-injections")["test"]
deepset_attacks = [t for t, l in zip(deepset_test["text"], deepset_test["label"]) if l == 1]
deepset_benign = [t for t, l in zip(deepset_test["text"], deepset_test["label"]) if l == 0]

dolly = load_dataset("databricks/databricks-dolly-15k", split="train")
candidates = sorted({t.strip() for t in dolly["instruction"]
                     if 15 < len(t.strip()) < 300 and t.strip().lower() not in train_set})
dolly_unseen = random.Random(7).sample(candidates, 100)

SETS = [
    ("Your attacks",          my_attacks,      True),
    ("deepset test: attacks", deepset_attacks, True),
    ("Your hard benign",      my_benign,       False),
    ("deepset test: benign",  deepset_benign,  False),
    ("Dolly unseen: benign",  dolly_unseen,    False),
]

# ------------------------------------------------------------------ #
# Detectors: same defaults the gateway uses
# ------------------------------------------------------------------ #
kw = KeywordDetector()
sim = SimilarityDetector()
clf = ClassifierDetector(encoder=sim.model)
print(f"Thresholds: similarity {sim.threshold}, classifier {clf.threshold} (not tuned in this script)")


def verdicts(text: str) -> dict[str, bool]:
    k = bool(kw.scan(text))
    s = sim.best_match(text)[0] >= sim.threshold
    c = clf.probability(text) >= clf.threshold
    return {"Keyword": k, "Similarity": s, "Classifier": c, "Combined": k or s or c}


NAMES = ["Keyword", "Similarity", "Classifier", "Combined"]
results, flagged_texts = {}, {}
for label, texts, is_attack in SETS:
    counts = {n: 0 for n in NAMES}
    flagged_texts[label] = []
    for t in texts:
        v = verdicts(t)
        for n in NAMES:
            counts[n] += v[n]
        if v["Combined"] != is_attack:           # a miss (attack) or a false positive (benign)
            flagged_texts[label].append(t)
    results[label] = {"n": len(texts), "is_attack": is_attack, "counts": counts}


def show(title: str, want_attack: bool):
    print(f"\n=== {title} ===")
    print(f"{'Set':24} {'n':>4} " + " ".join(f"{n:>13}" for n in NAMES) + "   Combined 95% CI")
    for label, r in results.items():
        if r["is_attack"] != want_attack:
            continue
        n = r["n"]
        cells = " ".join(f"{r['counts'][x]}/{n} ({r['counts'][x] / n:.0%})".rjust(13) for x in NAMES)
        lo, hi = wilson(r["counts"]["Combined"], n)
        print(f"{label:24} {n:>4} {cells}   {lo:.0%}-{hi:.0%}")


show("Attack sets: detection rate (higher is better)", True)
show("Benign sets: false-positive rate (lower is better)", False)

print("\n=== Combined misses and false positives (record these as limitations; do NOT tune on them) ===")
for label, items in flagged_texts.items():
    kind = "MISSED" if results[label]["is_attack"] else "FALSE POSITIVE"
    print(f"\n{label}: {len(items)} {kind}")
    for t in items[:15]:
        print(f"   - {t[:100]!r}")

Path("reports").mkdir(exist_ok=True)
Path("reports/clean_test_results.json").write_text(json.dumps({
    "thresholds": {"similarity": sim.threshold, "classifier": clf.threshold},
    "results": results,
    "flagged": flagged_texts,
}, indent=2), encoding="utf-8")
print("\nSaved to reports/clean_test_results.json")