from contextlib import AsyncExitStack

from mcp import Client, StdioServerParameters

SEP = "__"


class ServerPool:
    """Connects to several MCP servers and exposes their tools as one namespaced set."""

    def __init__(self, servers: dict[str, StdioServerParameters]):
        self.servers = servers
        self.clients: dict[str, Client] = {}
        self._stack = AsyncExitStack()

    async def __aenter__(self):
        await self._stack.__aenter__()
        for name, params in self.servers.items():
            self.clients[name] = await self._stack.enter_async_context(Client(params))
        return self

    async def __aexit__(self, *exc):
        return await self._stack.__aexit__(*exc)

    async def tool_defs(self) -> list[dict]:
        """All tools in Ollama's format, named 'server__tool'."""
        defs = []
        for server, client in self.clients.items():
            for t in (await client.list_tools()).tools:
                defs.append({
                    "type": "function",
                    "function": {
                        "name": f"{server}{SEP}{t.name}",
                        "description": t.description or "",
                        "parameters": t.input_schema,
                    },
                })
        return defs

    async def call_tool(self, namespaced: str, args: dict):
        server, _, tool = namespaced.partition(SEP)
        if server not in self.clients:
            raise KeyError(f"Unknown server in tool name: {namespaced}")
        return await self.clients[server].call_tool(tool, args)