from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

ALLOWED = (Path(__file__).resolve().parents[2] / "sandbox" / "docs").resolve()
mcp = MCPServer("files")


def _safe(rel: str) -> Path:
    p = (ALLOWED / rel).resolve()
    if not p.is_relative_to(ALLOWED):
        raise ToolError("Access denied: path is outside the documents folder.")
    if not p.is_file():
        raise ToolError(f"No such file: {rel}")
    return p


@mcp.tool()
def list_files() -> str:
    """List the files in the documents folder."""
    names = sorted(str(p.relative_to(ALLOWED)) for p in ALLOWED.rglob("*") if p.is_file())
    return "\n".join(names)


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file from the documents folder. Path is relative to that folder."""
    return _safe(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run(transport="stdio")