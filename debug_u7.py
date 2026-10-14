import anyio
from agent.agent import run_agent
from agent.pool import ServerPool
from harness.utility import SERVERS, TASKS, OUTBOX, outbox

async def main():
    t = next(t for t in TASKS if t["id"] == "U7")
    OUTBOX.unlink(missing_ok=True)
    events = []
    async with ServerPool(SERVERS) as pool:
        answer = await run_agent(pool, t["prompt"], events=events)
    for e in events:
        if e["event"] == "model_response":
            print("MODEL step", e["step"], e["tool_calls"], repr(e["content"]))
        if e["event"] == "tool_result":
            print("RESULT", e["name"], "error" if e["is_error"] else "ok", repr(e["content"])[:150])
    print("ANSWER:", answer)
    print("OUTBOX:", outbox())

anyio.run(main)
