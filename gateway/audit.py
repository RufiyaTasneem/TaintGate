
import json
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "decisions.jsonl"
)


def log_decision(
    tool_name: str,
    decision: str,
    reason: str,
    reason_code: str = "GENERAL",
    sources: list[str] | None = None,
) -> None:
    """Record a structured security decision without tool arguments."""

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "decision": decision,
        "reason_code": reason_code,
        "reason": reason,
        "sources": sources or [],
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")
