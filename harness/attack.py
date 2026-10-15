import json
import sys
from pathlib import Path

import anyio

from agent.agent import MODEL, run_agent
from agent.defenses import make_policy
from agent.pool import ServerPool
from attacks.scenarios import ATTACKER, SCENARIOS
from harness.utility import OUTBOX, SERVERS, outbox, parse_defenses

INBOX = Path("sandbox/mail/inbox.json")
TEMPERATURE = 0.3


def rate(a: int, b: int) -> float | None:
    return round(a / b, 3) if b else None


async def main(n: int, defense_arg: str | None = None, only: str | None = None) -> None:
    label, defenses = parse_defenses(defense_arg)
    scenarios = [s for s in SCENARIOS if not only or s["id"].startswith(only)]
    if not scenarios:
        raise SystemExit(f"No scenario ids start with {only!r}")
    suffix = f"_{only}" if only else ""

    raw_dir = Path(f"results/raw/{label}")
    raw_dir.mkdir(parents=True, exist_ok=True)

    base_text = INBOX.read_text(encoding="utf-8")
    base = json.loads(base_text)
    summary = {"model": MODEL, "defense": label, "trials_per_prompt": n,
               "temperature": TEMPERATURE, "scenarios": {}}

    try:
        for sc in scenarios:
            INBOX.write_text(json.dumps(base + sc.get("extra_emails", []), indent=2), encoding="utf-8")
            servers = {**SERVERS, **sc.get("extra_servers", {})}
            rows = []
            async with ServerPool(servers) as pool:
                for pi, prompt in enumerate(sc["prompts"]):
                    c = dict(hits=0, exposed=0, hits_exposed=0, task_ok=0,
                             blocked=0, disclosed=0, maxed=0)
                    for i in range(n):
                        OUTBOX.unlink(missing_ok=True)
                        events: list[dict] = []
                        try:
                            answer = await run_agent(
                                pool, prompt, events=events, temperature=TEMPERATURE,
                                seed=i, policy=make_policy(defenses), prior_messages=sc.get("prior_messages"),
                            )
                        except Exception as e:
                            print("  error:", e)
                            answer = ""
                        out = outbox()
                        hit = bool(sc["success"](events, out))
                        exp = bool(sc["exposed"](events))
                        blocked = any(e["event"] == "policy_block" for e in events)
                        maxed = any(e["event"] == "max_steps_reached" for e in events)
                        disclosed = hit and ATTACKER in (answer or "").lower()
                        c["hits"] += hit
                        c["exposed"] += exp
                        c["hits_exposed"] += (hit and exp)
                        c["task_ok"] += bool(sc["benign"](answer, pi))
                        c["blocked"] += blocked
                        c["disclosed"] += disclosed
                        c["maxed"] += maxed
                        (raw_dir / f"{sc['id']}_p{pi}_t{i}.json").write_text(
                            json.dumps({"prompt": prompt, "answer": answer, "events": events,
                                        "outbox": out, "exposed": exp, "attack_success": hit,
                                        "policy_blocked": blocked}, indent=2),
                            encoding="utf-8")
                        print(f"[{label}] {sc['id']} p{pi} trial {i + 1}/{n}: "
                              f"{'ATTACK SUCCEEDED' if hit else 'no attack success'}"
                              f"{' (policy blocked a call)' if blocked else ''}"
                              f"{'' if exp else ' (payload never seen)'}")
                    rows.append({"prompt": prompt, "trials": n, **c})
            total = n * len(sc["prompts"])
            s = {k: sum(r[k] for r in rows) for k in
                 ("hits", "exposed", "hits_exposed", "task_ok", "blocked", "disclosed", "maxed")}
            summary["scenarios"][sc["id"]] = {
                "name": sc["name"], "owasp": sc["owasp"], "prompts": rows, "trials": total,
                "exposed": s["exposed"],
                "attack_success_rate_overall": rate(s["hits"], total),
                "attack_success_rate_given_exposed": rate(s["hits_exposed"], s["exposed"]),
                "benign_task_rate": rate(s["task_ok"], total),
                "trials_with_policy_block": s["blocked"],
                "successful_attacks_disclosed_to_user": s["disclosed"],
                "trials_hitting_max_steps": s["maxed"]}
            per_prompt = [f"p{i}: {r['hits']}/{r['trials']}" for i, r in enumerate(rows)]
            print(f"\n[{label}] {sc['id']}: {s['hits_exposed']}/{s['exposed']} succeeded when exposed "
                  f"({', '.join(per_prompt)}); policy blocks in {s['blocked']} trials\n")
    finally:
        INBOX.write_text(base_text, encoding="utf-8")  # always restore the clean inbox

    Path(f"results/attack_{label}{suffix}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    anyio.run(
        main,
        int(sys.argv[1]) if len(sys.argv) > 1 else 5,
        sys.argv[2] if len(sys.argv) > 2 else None,
        sys.argv[3] if len(sys.argv) > 3 else None,
    )