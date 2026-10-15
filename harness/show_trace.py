import json
import sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
print("PROMPT:", d["prompt"])
for e in d["events"]:
    kind = e["event"]
    if kind == "tools_quarantined":
        print("  [QUARANTINED]", [r["name"] for r in e["removed"]])
    elif kind == "model_response":
        if e["tool_calls"]:
            for c in e["tool_calls"]:
                print("  agent calls", c["name"], str(c["args"])[:90])
        else:
            print("  agent replies (final answer)")
    elif kind == "tool_result":
        print("    result:", e["content"][:60].replace("\n", " "))
    elif kind == "policy_block":
        print("  [BLOCKED]", e["name"], "-", e["reason"])
print("ANSWER:", (d["answer"] or "")[:160].replace("\n", " "))
print("ATTACK SUCCEEDED:", d["attack_success"])
