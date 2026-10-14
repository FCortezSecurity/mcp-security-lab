import sys
import anyio
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

params = StdioServerParameters(
    command=sys.executable,
    args=["servers/benign/email_server.py"],
)

async def main() -> None:
    async with Client(params) as client:
        tools = await client.list_tools()
        print("TOOLS:", [t.name for t in tools.tools])

        r = await client.call_tool("list_emails", {})
        print("LIST:", [b.text for b in r.content if isinstance(b, TextContent)])

        r = await client.call_tool("send_email", {"to": "test@example.test", "subject": "hi", "body": "hello"})
        print("SEND is_error:", r.is_error, [b.text for b in r.content if isinstance(b, TextContent)])

if __name__ == "__main__":
    anyio.run(main)
