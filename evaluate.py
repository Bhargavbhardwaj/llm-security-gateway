import json
from pathlib import Path

from detectors.keyword_detector import KeywordDetector
from detectors.similarity_detector import SimilarityDetector
from detectors.classifier_detector import ClassifierDetector

DATA = Path("data")
attacks = json.loads((DATA / "eval_attacks.json").read_text(encoding="utf-8"))
benign = json.loads((DATA / "eval_benign.json").read_text(encoding="utf-8"))

kw = KeywordDetector()
sim = SimilarityDetector()
clf = ClassifierDetector(encoder=sim.model)   # reuse the already-loaded encoder

rows = []
for category, prompts in attacks.items():
    for p in prompts:
        rows.append({"label": "attack", "category": category, "text": p})
for p in benign:
    rows.append({"label": "benign", "category": "benign", "text": p})

for r in rows:
    r["kw"] = bool(kw.scan(r["text"]))
    r["score"] = sim.best_match(r["text"])[0]
    r["clf"] = clf.probability(r["text"])


def metrics(predict):
    tp = sum(1 for r in rows if r["label"] == "attack" and predict(r))
    fn = sum(1 for r in rows if r["label"] == "attack" and not predict(r))
    fp = sum(1 for r in rows if r["label"] == "benign" and predict(r))
    tn = sum(1 for r in rows if r["label"] == "benign" and not predict(r))
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "detection_rate": tp / (tp + fn) if tp + fn else 0,
        "fpr": fp / (fp + tn) if fp + tn else 0,
        "precision": tp / (tp + fp) if tp + fp else 0,
    }


T, C = sim.threshold, clf.threshold
detectors = {
    "Keyword only":    lambda r: r["kw"],
    "Similarity only": lambda r: r["score"] >= T,
    "Classifier only": lambda r: r["clf"] >= C,
    "Combined":        lambda r: r["kw"] or r["score"] >= T or r["clf"] >= C,
}

print(f"\n=== Overall (similarity threshold = {T}, classifier threshold = {C}) ===")
print(f"{'Detector':16} | {'Detection':>9} | {'False pos':>9} | {'Precision':>9}")
results = {}
for name, fn in detectors.items():
    m = metrics(fn)
    results[name] = m
    print(f"{name:16} | {m['detection_rate']:9.0%} | {m['fpr']:9.0%} | {m['precision']:9.0%}")

print("\n=== Detection by category ===")
print(f"{'Category':28} {'Keyword':>8} {'Simil.':>8} {'Classif.':>9} {'Combined':>9}")
for category in attacks:
    cat_rows = [r for r in rows if r["category"] == category]
    n = len(cat_rows)
    cells = [sum(1 for r in cat_rows if detectors[d](r)) for d in
             ("Keyword only", "Similarity only", "Classifier only", "Combined")]
    print(f"{category:28} " + " ".join(f"{c}/{n}".rjust(8) for c in cells))

print("\n=== MISSED ATTACKS (Combined) ===")
for r in rows:
    if r["label"] == "attack" and not detectors["Combined"](r):
        print(f"  sim {r['score']:.2f} | clf {r['clf']:.2f} | [{r['category']}] {r['text'][:80]}")

print("\n=== FALSE POSITIVES (Combined) ===")
for r in rows:
    if r["label"] == "benign" and detectors["Combined"](r):
        print(f"  sim {r['score']:.2f} | clf {r['clf']:.2f} | kw={r['kw']} | {r['text'][:80]}")

print("\n=== Classifier threshold sweep (Combined, similarity fixed) ===")
print(f"{'Clf thr':>8} | {'Detection':>9} | {'False pos':>9}")
sweep = []
for t in [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
    m = metrics(lambda r, t=t: r["kw"] or r["score"] >= T or r["clf"] >= t)
    sweep.append({"threshold": t, **m})
    print(f"{t:8.2f} | {m['detection_rate']:9.0%} | {m['fpr']:9.0%}")

Path("reports").mkdir(exist_ok=True)
Path("reports/eval_results.json").write_text(
    json.dumps({"threshold": T, "classifier_threshold": C,
                "results": results, "sweep": sweep}, indent=2),
    encoding="utf-8",
)
print("\nSaved to reports/eval_results.json")