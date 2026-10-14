import json
import random
from pathlib import Path

import joblib
from datasets import load_dataset
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

random.seed(42)
DATA = Path("data")

# 1. deepset (labeled injections + legit prompts)
ds = load_dataset("deepset/prompt-injections")
texts = list(ds["train"]["text"])
labels = list(ds["train"]["label"])
test_texts, test_labels = ds["test"]["text"], ds["test"]["label"]

# 2. Your own training attack library as extra positives
attack_lib = json.loads((DATA / "attack_prompts.json").read_text(encoding="utf-8"))
for prompts in attack_lib.values():
    for p in prompts:
        texts.append(p)
        labels.append(1)

# 3. Held-out eval prompts: must NEVER enter training
eval_attacks = json.loads((DATA / "eval_attacks.json").read_text(encoding="utf-8"))
eval_benign = json.loads((DATA / "eval_benign.json").read_text(encoding="utf-8"))
eval_set = {p.strip().lower() for ps in eval_attacks.values() for p in ps}
eval_set |= {p.strip().lower() for p in eval_benign}

# 4. Benign instructions from Dolly as negatives
dolly = load_dataset("databricks/databricks-dolly-15k", split="train")
print("Dolly columns:", dolly.column_names)
pool = [t.strip() for t in dolly["instruction"] if 15 < len(t.strip()) < 300]
random.shuffle(pool)
benign_extra = [t for t in pool if t.lower() not in eval_set][:1500]

# 5. Optional: your own hand-written hard negatives (NOT copies of eval_benign.json)
hard_file = DATA / "train_benign.txt"
if hard_file.exists():
    for line in hard_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and line.lower() not in eval_set:
            benign_extra.append(line)

texts += benign_extra
labels += [0] * len(benign_extra)
Path("models").mkdir(exist_ok=True)
Path("models/train_texts.json").write_text(json.dumps(texts), encoding="utf-8")
print(f"Training set: {len(texts)} prompts "
      f"({sum(labels)} injections, {len(labels) - sum(labels)} benign)")

encoder = SentenceTransformer("all-MiniLM-L6-v2")
X_train = encoder.encode(texts, normalize_embeddings=True, show_progress_bar=True)
X_test = encoder.encode(test_texts, normalize_embeddings=True)

clf = LogisticRegression(max_iter=1000, class_weight="balanced")
clf.fit(X_train, labels)

print(classification_report(test_labels, clf.predict(X_test),
                            target_names=["benign", "injection"]))

Path("models").mkdir(exist_ok=True)
joblib.dump(clf, "models/injection_clf.joblib")
print("Saved models/injection_clf.joblib")