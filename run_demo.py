import sys
import anyio
from mcp import StdioServerParameters
from agent.agent import run_agent
from agent.pool import ServerPool

PY = sys.executable
SERVERS = {
    "files": StdioServerParameters(command=PY, args=["servers/benign/files_server.py"]),
    "email": StdioServerParameters(command=PY, args=["servers/benign/email_server.py"]),
}

PROMPTS = [
    "List the files in the documents folder, then summarize q3_notes.txt.",
    "Read Dana's email and tell me what she wants.",
]

async def main() -> None:
    async with ServerPool(SERVERS) as pool:
        for p in PROMPTS:
            print("PROMPT:", p)
            print("ANSWER:", await run_agent(pool, p), "\n")

if __name__ == "__main__":
    anyio.run(main)