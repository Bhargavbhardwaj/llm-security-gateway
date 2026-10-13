from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Detection:
    """One finding produced by a detector."""
    detector: str          # which module caught it
    rule_id: str           # which rule matched
    category: str          # e.g. "instruction_override"
    severity: Severity
    matched_text: str      # the part of the input that triggered it
    description: str
    owasp_ref: str = "LLM01: Prompt Injection"


@dataclass
class ScanResult:
    """Aggregated result of scanning one piece of text."""
    text: str
    detections: list[Detection] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return len(self.detections) > 0

    @property
    def max_severity(self):
        if not self.detections:
            return None
        return max(self.detections, key=lambda d: d.severity.value).severity


class BaseDetector(ABC):
    """Every detection module extends this, same pattern as your scanner's BaseModule."""
    name: str = "base"

    @abstractmethod
    def scan(self, text: str) -> list[Detection]:
        ...