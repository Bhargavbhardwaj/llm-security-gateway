from pathlib import Path

import joblib
from sentence_transformers import SentenceTransformer

from .base import BaseDetector, Detection, Severity

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "injection_clf.joblib"


class ClassifierDetector(BaseDetector):
    """Supervised classifier on sentence embeddings, trained on labeled injection data."""
    name = "ClassifierDetector"

    def __init__(self, threshold: float = 0.70, encoder=None):
        self.threshold = threshold
        self.encoder = encoder or SentenceTransformer("all-MiniLM-L6-v2")
        self.clf = joblib.load(MODEL_PATH)

    def probability(self, text: str) -> float:
        emb = self.encoder.encode([text], normalize_embeddings=True)
        return float(self.clf.predict_proba(emb)[0][1])

    def scan(self, text: str) -> list[Detection]:
        p = self.probability(text)
        if p < self.threshold:
            return []
        return [Detection(
            detector=self.name,
            rule_id="CLF-001",
            category="classifier_flag",
            severity=Severity.HIGH if p >= 0.8 else Severity.MEDIUM,
            matched_text=text[:80],
            description=f"Classifier injection probability {p:.2f}",
        )]