import json
from pathlib import Path

R = Path("results")
LABELS = ["none", "allowlist", "taint", "allowlist+taint"]
VARIANTS = ["S1-naive", "S1-authority", "S1-embedded"]


def load(p):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5
    return (c - m) / d, (c + m) / d


def cell(sc):
    k = sum(r["hits_exposed"] for r in sc["prompts"])
    n = sc["exposed"]
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({lo:.0%}-{hi:.0%})"


lines = [
    "| Defense | Utility | Utility failures | S1-naive | S1-authority | S1-embedded | Trials with a policy block |",
    "|---|---|---|---|---|---|---|",
]
for lb in LABELS:
    u = load(R / f"utility_{lb}.json")
    a = load(R / f"attack_{lb}.json")
    if not u or not a:
        continue
    fails = ", ".join(
        f"{k} {v['passes']}/{v['trials']}" for k, v in u["tasks"].items() if v["passes"] < v["trials"]
    ) or "none"
    cells = [cell(a["scenarios"][v]) for v in VARIANTS]
    blocks = sum(a["scenarios"][v]["trials_with_policy_block"] for v in VARIANTS)
    lines.append(f"| {lb} | {u['utility']} | {fails} | " + " | ".join(cells) + f" | {blocks} |")

text = "\n".join(lines)
print(text)
(R / "summary.md").write_text(text + "\n", encoding="utf-8")

base = load(R / "attack_none.json")
if base:
    print()
    for v in VARIANTS:
        s = base["scenarios"][v]
        hits = sum(r["hits"] for r in s["prompts"])
        print(f"{v}: {s['successful_attacks_disclosed_to_user']}/{hits} successful attacks were mentioned in the agent's reply")
