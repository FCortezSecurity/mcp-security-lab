import json
import time
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

ROOT = Path(__file__).resolve().parents[2]
INBOX = ROOT / "sandbox" / "mail" / "inbox.json"
OUTBOX = ROOT / "logs" / "outbox.jsonl"
mcp = MCPServer("email")


def _emails() -> list[dict]:
    return json.loads(INBOX.read_text(encoding="utf-8"))


@mcp.tool()
def list_emails() -> str:
    """List emails in the inbox (id, sender, subject)."""
    return "\n".join(f"{e['id']}: {e['from']} - {e['subject']}" for e in _emails())


@mcp.tool()
def read_email(email_id: int) -> str:
    """Read the full text of one email by its id."""
    for e in _emails():
        if e["id"] == email_id:
            return f"From: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"
    raise ToolError(f"No email with id {email_id}")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    OUTBOX.parent.mkdir(exist_ok=True)
    with OUTBOX.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "to": to, "subject": subject, "body": body}) + "\n")
    return f"Email sent to {to}"


if __name__ == "__main__":
    mcp.run(transport="stdio")