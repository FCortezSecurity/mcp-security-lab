import glob
import json
from pathlib import Path

R = Path("results")
LABELS = ["none", "allowlist+taint", "descscan", "egress", "descscan+egress"]


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5
    return max(0.0, (c - m) / d), min(1.0, (c + m) / d)


def quarantined(label, arm):
    n = 0
    for f in glob.glob(f"results/raw/{label}/S2c-{arm}_*.json"):
        d = json.load(open(f, encoding="utf-8"))
        n += any(e["event"] == "tools_quarantined" for e in d["events"])
    return n


rows = [
    "| Defense | exfil: marker leaked | control: marker leaked | exfil: weather answered | control: weather answered | exfil trials with a block | exfil trials with a tool quarantined |",
    "|---|---|---|---|---|---|---|",
]
for lb in LABELS:
    p = R / f"attack_{lb}_S2c.json"
    if not p.exists():
        continue
    s = json.load(open(p, encoding="utf-8"))["scenarios"]
    ex, co = s["S2c-ctx_exfil"], s["S2c-ctx_control"]
    kx = sum(r["hits"] for r in ex["prompts"])
    kc = sum(r["hits"] for r in co["prompts"])
    a, b = wilson(kx, ex["trials"])
    c, d = wilson(kc, co["trials"])
    rows.append(
        f"| {lb} | {kx}/{ex['trials']} ({a:.0%}-{b:.0%}) | {kc}/{co['trials']} ({c:.0%}-{d:.0%}) "
        f"| {ex['benign_task_rate']:.2f} | {co['benign_task_rate']:.2f} "
        f"| {ex['trials_with_policy_block']} | {quarantined(lb, 'ctx_exfil')} |"
    )
text = "\n".join(rows)
print(text)
(R / "summary_s2c.md").write_text(text + "\n", encoding="utf-8")
