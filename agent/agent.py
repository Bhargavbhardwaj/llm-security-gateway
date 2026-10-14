import json

from llm_client import chat_json
from agent.tools import TOOLS

SYSTEM_TEMPLATE = """You are a helpful assistant that can use tools.
Reply with ONE JSON object per turn and nothing else.

To use a tool: {"tool": "<tool_name>", "args": {...}}
To answer the user: {"final": "<your answer>"}

Available tools:
__TOOLS__

The user's files are in the workspace/ folder (for example workspace/notes.txt and workspace/todo.txt).
You cannot read files or do reliable arithmetic yourself.
For any question about a file, you MUST call read_file first.
For any calculation, you MUST call calculator.
For any question about current news or web content, you MUST call web_search.
Never say you lack access before trying the tool.
Use tools only when needed. Once you have the information, reply with {"final": "..."}."""

FOLLOWUP = 'Continue. Reply with JSON only: another tool call, or {"final": "..."}.'

KILL_MESSAGE = "Session terminated by the guardrail kill switch after repeated policy violations."


class Agent:
    def __init__(self, policy=None, max_steps: int = 5):
        """policy=None gives the unprotected baseline agent."""
        self.policy = policy
        self.max_steps = max_steps
        tool_list = "\n".join(f"- {n}: {t['desc']}" for n, t in TOOLS.items())
        self.system = SYSTEM_TEMPLATE.replace("__TOOLS__", tool_list)

    def execute_tool(self, name, args) -> str:
        """Single choke point for every tool call. The policy layer plugs in HERE."""
        if self.policy is not None:
            decision = self.policy.check(name, args)
            if not decision.allowed:
                return f"BLOCKED BY GUARDRAIL [{decision.rule_id}]: {decision.reason}"
            if decision.args is not None:
                args = decision.args          # run with the sanitized arguments

        if not isinstance(name, str) or name not in TOOLS:
            return f"ERROR: unknown tool '{name}'"
        try:
            result = str(TOOLS[name]["fn"](**args))
        except Exception as e:
            result = f"ERROR: {e}"

        if self.policy is not None:
            result = self.policy.inspect_result(name, result)
        return result

    def run(self, task: str) -> str:
        if self.policy is not None:
            self.policy.reset()

        messages = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": task},
        ]
        for step in range(1, self.max_steps + 1):
            raw = chat_json(messages)
            try:
                action = json.loads(raw)
                if not isinstance(action, dict):
                    raise ValueError
            except ValueError:
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content": "Invalid reply. " + FOLLOWUP})
                continue

            if "final" in action:
                return str(action["final"]).strip() or "(the model returned an empty answer)"

            name = action.get("tool")
            args = action.get("args", {})
            result = self.execute_tool(name, args)
            print(f"  [step {step}] tool={name} args={args}")
            print(f"            -> {result[:150]}")

            if self.policy is not None and self.policy.killed:
                return KILL_MESSAGE

            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": f"TOOL RESULT from {name}:\n{result}\n\n{FOLLOWUP}",
            })
        return "Stopped: reached the maximum number of steps."