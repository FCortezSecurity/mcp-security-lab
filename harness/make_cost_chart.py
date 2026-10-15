import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = Path("results")
OUT = Path("docs/img/cost.png")


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5
    return max(0.0, (c - m) / d), min(1.0, (c + m) / d)


def s1_utility(label):
    path = R / f"utility_{label}.json"
    if not path.exists():
        print("missing:", path)
        return None
    tasks = json.loads(path.read_text(encoding="utf-8"))["tasks"].values()
    return sum(v["passes"] for v in tasks), sum(v["trials"] for v in tasks)


def s2e_answered(label):
    path = R / f"attack_{label}_S2e.json"
    if not path.exists():
        print("missing:", path)
        return None
    sc = json.loads(path.read_text(encoding="utf-8"))["scenarios"]["S2e-ctx_control_addr"]
    return sum(p["task_ok"] for p in sc["prompts"]), sc["trials"]


PANELS = [
    ("S1 suite: normal tasks completed", s1_utility, ["none", "allowlist", "taint", "allowlist+taint"]),
    ("S2e: benign tool, user mentions an address", s2e_answered, ["none", "egress", "egress2"]),
]

fig, axes = plt.subplots(1, 2, figsize=(10.5, 5.2), sharey=True, gridspec_kw={"width_ratios": [4, 3]})
for ax, (title, fn, labels) in zip(axes, PANELS):
    xs, rates, lows, highs, texts, colors = [], [], [], [], [], []
    for lb in labels:
        got = fn(lb)
        if got is None:
            continue
        k, n = got
        lo, hi = wilson(k, n)
        r = k / n
        xs.append(lb)
        rates.append(r * 100)
        lows.append((r - lo) * 100)
        highs.append((hi - r) * 100)
        texts.append(f"{k}/{n}")
        colors.append("#7a7a7a" if lb == "none" else "#2f6f9f")
    pos = list(range(len(xs)))
    ax.bar(pos, rates, color=colors, yerr=[lows, highs], capsize=4, ecolor="#333333")
    for i, (r, h, t) in enumerate(zip(rates, highs, texts)):
        ax.text(i, min(r + h, 100) + 2, t, ha="center", va="bottom", fontsize=10)
    ax.set_xticks(pos)
    ax.set_xticklabels(xs, rotation=25, ha="right")
    ax.set_title(title, fontsize=11)
    ax.set_ylim(0, 115)
    ax.spines[["top", "right"]].set_visible(False)

axes[0].set_ylabel("Requests completed (%)")
fig.suptitle("What the defenses cost: legitimate requests still completed", fontsize=14)
fig.text(0.5, 0.01,
         "Higher is better. Grey = no defense. S1 panel: 9 task types x 5 trials. S2e panel: 3 prompts x 10 trials. "
         "qwen2.5:7b, temperature 0.3. 95% Wilson intervals.",
         ha="center", fontsize=8.5, color="#555555")
fig.tight_layout(rect=[0, 0.05, 1, 0.94])
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, dpi=160, facecolor="white")
print("saved", OUT)
