import sys
import anyio
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

params = StdioServerParameters(
    command=sys.executable,  # uses the venv's python, not a bare "python"
    args=["servers/benign/hello_server.py"],
)

async def main() -> None:
    async with Client(params) as client:
        tools = await client.list_tools()
        for t in tools.tools:
            print("TOOL:", t.name, "-", t.description)
            print("SCHEMA:", t.input_schema)

        result = await client.call_tool("add", {"a": 2, "b": 3})
        print("is_error:", result.is_error)
        print("structured:", result.structured_content)
        for block in result.content:
            if isinstance(block, TextContent):
                print("text:", block.text)

if __name__ == "__main__":
    anyio.run(main)