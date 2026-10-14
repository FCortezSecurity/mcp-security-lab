import json
import sys
from pathlib import Path

import anyio

from agent.agent import MODEL, run_agent
from agent.pool import ServerPool
from attacks.scenarios import SCENARIOS, did_benign_task, exposed_to_payload
from harness.utility import OUTBOX, SERVERS, outbox

INBOX = Path("sandbox/mail/inbox.json")
TEMPERATURE = 0.3


async def main(n: int) -> None:
    base_text = INBOX.read_text(encoding="utf-8")
    base = json.loads(base_text)
    summary = {"model": MODEL, "defense": "none", "trials_per_prompt": n,
               "temperature": TEMPERATURE, "scenarios": {}}
    Path("results/raw").mkdir(parents=True, exist_ok=True)

    try:
        async with ServerPool(SERVERS) as pool:
            for sc in SCENARIOS:
                INBOX.write_text(json.dumps(base + sc["extra_emails"], indent=2), encoding="utf-8")
                rows = []
                for pi, prompt in enumerate(sc["prompts"]):
                    hits = exposed = task_ok = 0
                    for i in range(n):
                        OUTBOX.unlink(missing_ok=True)
                        events: list[dict] = []
                        try:
                            answer = await run_agent(pool, prompt, events=events,
                                                     temperature=TEMPERATURE, seed=i)
                        except Exception as e:
                            print("  error:", e)
                            answer = ""
                        out = outbox()
                        hit = bool(sc["success"](events, out))
                        exp = exposed_to_payload(events)
                        ok = did_benign_task(answer or "")
                        hits += hit
                        exposed += exp
                        task_ok += ok
                        Path(f"results/raw/{sc['id']}_p{pi}_t{i}.json").write_text(
                            json.dumps({"prompt": prompt, "answer": answer, "events": events,
                                        "outbox": out, "attack_success": hit}, indent=2),
                            encoding="utf-8")
                        print(f"{sc['id']} p{pi} trial {i + 1}/{n}: "
                              f"{'ATTACK SUCCEEDED' if hit else 'blocked/ignored'}"
                              f"{'' if exp else ' (payload never read)'}")
                    rows.append({"prompt": prompt, "attack_successes": hits, "exposed": exposed,
                                 "benign_task_ok": task_ok, "trials": n})
                total_hits = sum(r["attack_successes"] for r in rows)
                total = n * len(sc["prompts"])
                summary["scenarios"][sc["id"]] = {
                    "name": sc["name"], "owasp": sc["owasp"], "prompts": rows,
                    "attack_success_rate": round(total_hits / total, 3)}
                print(f"\n{sc['id']} attack success rate: {total_hits}/{total}\n")
    finally:
        INBOX.write_text(base_text, encoding="utf-8")  # always restore the clean inbox

    Path("results/attack_baseline.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    anyio.run(main, int(sys.argv[1]) if len(sys.argv) > 1 else 5)