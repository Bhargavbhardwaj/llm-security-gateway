import json
import re
from pathlib import Path

from sentence_transformers import SentenceTransformer, util

from .base import BaseDetector, Detection, Severity

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "attack_prompts.json"
MODEL_NAME = "all-MiniLM-L6-v2"


class SimilarityDetector(BaseDetector):
    """Flags input that is semantically close to a known attack prompt."""
    name = "SimilarityDetector"

    def __init__(self, threshold: float = 0.50, high_threshold: float = 0.80):
        self.threshold = threshold
        self.high_threshold = high_threshold
        self.model = SentenceTransformer(MODEL_NAME)

        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        self.attacks = [(cat, p) for cat, prompts in data.items() for p in prompts]
        self.attack_embeddings = self.model.encode(
            [p for _, p in self.attacks],
            convert_to_tensor=True,
            normalize_embeddings=True,
        )

    def best_match(self, text: str):
        """Return (score, category, closest_attack_prompt) for the text."""
        # Check the whole text AND each sentence, so an attack buried
        # inside a long, innocent-looking message is still caught.
        chunks = [text] + [s for s in re.split(r"(?<=[.!?])\s+|\n+", text) if len(s.strip()) > 3]
        chunks = list(dict.fromkeys(chunks))

        embeddings = self.model.encode(chunks, convert_to_tensor=True, normalize_embeddings=True)
        scores = util.cos_sim(embeddings, self.attack_embeddings)

        flat_index = int(scores.argmax())
        _, attack_idx = divmod(flat_index, scores.shape[1])
        category, attack_text = self.attacks[attack_idx]
        return float(scores.max()), category, attack_text

    def scan(self, text: str) -> list[Detection]:
        score, category, attack_text = self.best_match(text)
        if score < self.threshold:
            return []

        severity = Severity.HIGH if score >= self.high_threshold else Severity.MEDIUM
        return [Detection(
            detector=self.name,
            rule_id="SIM-001",
            category=category,
            severity=severity,
            matched_text=f"{text[:80]}",
            description=f"Semantically similar (score {score:.2f}) to known attack: '{attack_text}'",
        )]