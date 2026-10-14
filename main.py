from gateway import SecurityGateway

gateway = SecurityGateway()
print("LLM Security Gateway running. Type 'exit' to quit.\n")

while True:
    prompt = input("You: ")
    if prompt.strip().lower() == "exit":
        break
    result = gateway.process(prompt)
    print(f"[{result['status']}]", f"(severity: {result['severity']})" if result["severity"] else "")
    for d in result["detections"]:
        print(f"   -> {d.rule_id} {d.category}: '{d.matched_text}'")
    print("Model:", result["response"], "\n")