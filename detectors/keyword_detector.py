import re
from .base import BaseDetector, Detection, Severity

# (rule_id, category, severity, regex, description)
RULES = [
    ("KW-001", "instruction_override", Severity.HIGH,
     r"\b(ignore|disregard|forget|override|skip|discard|set aside|drop)\b.{0,30}\b(previous|prior|above|earlier|all|your|any|everything)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?|commands?|directives?|orders?|context|constraints?|restrictions?|programming|told)\b",
     "Attempts to override earlier instructions"),
    ("KW-002", "system_prompt_extraction", Severity.CRITICAL,
     r"\b(reveal|show|print|repeat|display|leak|tell me)\b.{0,30}\b(system prompt|initial prompt|hidden prompt|your instructions|your rules)\b",
     "Attempts to extract the system prompt"),
    ("KW-003", "role_hijack", Severity.HIGH,
     r"\b(you are now|act as|pretend to be|from now on you are|roleplay as)\b.{0,40}\b(dan|unrestricted|no restrictions|without (any )?(rules|limits|filters)|jailbroken)\b",
     "Attempts to reassign the model to an unrestricted role"),
    ("KW-004", "jailbreak_keyword", Severity.HIGH,
     r"\b(jailbreak|do anything now|dan mode)\b|\b(enter|enable|activate|switch to)\b.{0,20}\bdeveloper mode\b.{0,40}\b(ignore|bypass|no (rules|restrictions)|unrestricted)\b",
     "Known jailbreak terminology"),
    ("KW-005", "safety_bypass", Severity.MEDIUM,
     r"\b(bypass|disable|turn off|circumvent)\b.{0,30}\b(safety|filters?|guardrails?|restrictions?|moderation)\b",
     "Attempts to bypass safety controls"),
    ("KW-006", "delimiter_injection", Severity.MEDIUM,
     r"(<\|im_start\|>|<\|system\|>|\[INST\]|###\s*system|</?system>)",
     "Fake system/role delimiters injected into input"),
]


class KeywordDetector(BaseDetector):
    name = "KeywordDetector"

    def __init__(self):
        self.compiled = [
            (rid, cat, sev, re.compile(pattern, re.IGNORECASE | re.DOTALL), desc)
            for rid, cat, sev, pattern, desc in RULES
        ]

    def scan(self, text: str) -> list[Detection]:
        findings = []
        for rid, cat, sev, regex, desc in self.compiled:
            match = regex.search(text)
            if match:
                findings.append(Detection(
                    detector=self.name,
                    rule_id=rid,
                    category=cat,
                    severity=sev,
                    matched_text=match.group(0),
                    description=desc,
                ))
        return findings