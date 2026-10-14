import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"

MODEL = "phi3"                # used by the Phase 1 gateway (chat path)
AGENT_MODEL = "qwen2.5:3b"    # used by the Phase 2 agent (tool use)


def ask_llm(prompt: str, system: str | None = None) -> str:
    """Send a prompt to the local Ollama model and return its response text."""
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    }
    if system:
        payload["system"] = system
    response = requests.post(OLLAMA_URL, json=payload, timeout=120)
    response.raise_for_status()
    return response.json()["response"]


def chat_json(messages: list[dict]) -> str:
    """Multi-turn chat that forces the model to reply with valid JSON (used by the agent)."""
    payload = {
        "model": AGENT_MODEL,
        "messages": messages,
        "stream": False,
        "format": "json",
    }
    response = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=180)
    response.raise_for_status()
    return response.json()["message"]["content"]


if __name__ == "__main__":
    user_prompt = input("You: ")
    print("Model:", ask_llm(user_prompt))