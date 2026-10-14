import sys
import anyio
from mcp import Client, StdioServerParameters
from agent.agent import run_agent

params = StdioServerParameters(
    command=sys.executable,
    args=["servers/benign/hello_server.py"],
)

async def main() -> None:
    async with Client(params) as client:
        answer = await run_agent(client, "What is 17 plus 25? Use the tool.")
        print("ANSWER:", answer)

if __name__ == "__main__":
    anyio.run(main)