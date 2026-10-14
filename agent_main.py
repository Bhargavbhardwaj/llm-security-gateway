import sys

from agent.agent import Agent
from agent.policy import build_policy

if "--baseline" in sys.argv:
    agent = Agent(policy=None)
    print("Agent running in BASELINE mode (NO guardrails). Type 'exit' to quit.\n")
else:
    print("Loading guardrails (this loads the Phase 1 detectors, takes a few seconds)...")
    agent = Agent(policy=build_policy(use_ml=True))
    print("Agent running WITH guardrails. Type 'exit' to quit.\n")

while True:
    task = input("Task: ")
    if task.strip().lower() == "exit":
        break
    print("Answer:", agent.run(task), "\n")