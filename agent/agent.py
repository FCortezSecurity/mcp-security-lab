import json
import time
from pathlib import Path

import ollama
from mcp.types import TextContent

MODEL = "qwen2.5:7b"
LOG_PATH = Path("logs/agent.jsonl")


def log(event: str, **data) -> None:
    """Append one JSON event per line. Every prompt, tool call and result goes here."""
    LOG_PATH.parent.mkdir(exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "event": event, **data}) + "\n")


def to_ollama_tool(tool) -> dict:
    """Convert an MCP tool definition into Ollama's tool format."""
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.input_schema,
        },
    }


def result_text(result) -> str:
    return "\n".join(b.text for b in result.content if isinstance(b, TextContent))


async def run_agent(
    client,
    user_prompt: str,
    system_prompt: str = "You are a helpful assistant. Use the available tools when needed.",
    max_steps: int = 6,
) -> str | None:
    tools = [to_ollama_tool(t) for t in (await client.list_tools()).tools]
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    log("user_prompt", content=user_prompt, tools=[t["function"]["name"] for t in tools])

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
            step=step,
            content=msg.content,
            tool_calls=[{"name": c.function.name, "args": dict(c.function.arguments)} for c in calls],
        )

        if not calls:
            return msg.content  # model gave a final answer

        for call in calls:
            name, args = call.function.name, dict(call.function.arguments)
            # DEFENSE HOOK: policy checks (allowlist, approval, taint) will go here later
            result = await client.call_tool(name, args)
            text = result_text(result)
            log("tool_result", step=step, name=name, args=args, is_error=result.is_error, content=text)
            messages.append({"role": "tool", "tool_name": name, "content": text})

    log("max_steps_reached")
    return None