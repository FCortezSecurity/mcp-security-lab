import json
import time
from pathlib import Path

import ollama
from mcp.types import TextContent

MODEL = "qwen2.5:7b"
LOG_PATH = Path("logs/agent.jsonl")


def log(event: str, sink: list | None = None, **data) -> None:
    """Append one JSON event per line; optionally also collect it in `sink`."""
    rec = {"ts": time.time(), "event": event, **data}
    LOG_PATH.parent.mkdir(exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    if sink is not None:
        sink.append(rec)


def result_text(result) -> str:
    return "\n".join(b.text for b in result.content if isinstance(b, TextContent))


async def run_agent(
    pool,
    user_prompt: str,
    system_prompt: str = "You are a helpful assistant. Use the available tools when needed.",
    max_steps: int = 6,
    events: list | None = None,
) -> str | None:
    tools = await pool.tool_defs()
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    log("user_prompt", events, content=user_prompt, tools=[t["function"]["name"] for t in tools])

    for step in range(max_steps):
        resp = ollama.chat(
            model=MODEL,
            messages=messages,
            tools=tools,
            options={"temperature": 0, "seed": 42, "num_predict": 512},
        )
        msg = resp.message
        messages.append(msg)
        calls = msg.tool_calls or []
        log(
            "model_response",
            events,
            step=step,
            content=msg.content,
            tool_calls=[{"name": c.function.name, "args": dict(c.function.arguments)} for c in calls],
        )

        if not calls:
            return msg.content

        for call in calls:
            name, args = call.function.name, dict(call.function.arguments)
            # DEFENSE HOOK: policy checks (allowlist, approval, taint) go here later
            try:
                result = await pool.call_tool(name, args)
                text, is_error = result_text(result), result.is_error
            except Exception as e:
                text, is_error = f"Tool call failed: {e}", True
            log("tool_result", events, step=step, name=name, args=args, is_error=is_error, content=text)
            messages.append({"role": "tool", "tool_name": name, "content": text})

    log("max_steps_reached", events)
    return None