import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = Path("results")
OUT = Path("docs/img/results.png")

PANELS = [
    ("S1: injected email (naive payload)", "_S1", "S1-naive",
     ["none", "allowlist", "taint", "allowlist+taint"]),
    ("S2c: poisoned tool, data in its arguments", "_S2c", "S2c-ctx_exfil",
     ["none", "allowlist+taint", "descscan", "egress", "egress2"]),
    ("S2d: wording changed to evade descscan", "_S2d", "S2d-ctx_adaptive",
     ["none", "descscan", "egress", "egress2"]),
]


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5
    return max(0.0, (c - m) / d), min(1.0, (c + m) / d)


def load(label, suffix, scenario):
    path = R / f"attack_{label}{suffix}.json"
    if not path.exists():
        print("missing:", path)
        return None
    sc = json.loads(path.read_text(encoding="utf-8"))["scenarios"][scenario]
    k = sum(r["hits_exposed"] for r in sc["prompts"])
    return k, sc["exposed"]


fig, axes = plt.subplots(1, 3, figsize=(14, 5.4), sharey=True,
                         gridspec_kw={"width_ratios": [4, 5, 4]})
for ax, (title, suffix, scenario, labels) in zip(axes, PANELS):
    xs, rates, lows, highs, texts, colors = [], [], [], [], [], []
    for lb in labels:
        got = load(lb, suffix, scenario)
        if got is None:
            continue
        k, n = got
        lo, hi = wilson(k, n)
        r = k / n if n else 0
        xs.append(lb)
        rates.append(r * 100)
        lows.append((r - lo) * 100)
        highs.append((hi - r) * 100)
        texts.append(f"{k}/{n}")
        colors.append("#b0413e" if lb == "none" else "#2f6f9f")
    pos = list(range(len(xs)))
    ax.bar(pos, rates, color=colors, yerr=[lows, highs], capsize=4, ecolor="#333333")
    for i, (r, h, t) in enumerate(zip(rates, highs, texts)):
        ax.text(i, r + h + 2, t, ha="center", va="bottom", fontsize=10)
    ax.set_xticks(pos)
    ax.set_xticklabels(xs, rotation=25, ha="right")
    ax.set_title(title, fontsize=11)
    ax.set_ylim(0, 115)
    ax.spines[["top", "right"]].set_visible(False)

axes[0].set_ylabel("Attack success (%)")
fig.suptitle("Attack success with and without defenses", fontsize=14)
fig.text(0.5, 0.01,
         "30 trials per bar. qwen2.5:7b via Ollama, temperature 0.3. Error bars: 95% Wilson intervals. "
         "Red = no defense.",
         ha="center", fontsize=9, color="#555555")
fig.tight_layout(rect=[0, 0.05, 1, 0.94])
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, dpi=160, facecolor="white")
print("saved", OUT)
