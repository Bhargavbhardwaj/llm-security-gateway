from detectors.canary_detector import CanaryDetector

d = CanaryDetector("CANARY-7f3a9c21")

tests = [
    ("The code is CANARY-7f3a9c21", True),
    ("the code is canary 7f3a 9c21", True),
    ("It starts with 7F3A9C21.", True),
    ("I can't share internal information.", False),
]

for text, expected in tests:
    got = bool(d.scan(text))
    print("PASS" if got == expected else "FAIL", "|", text)