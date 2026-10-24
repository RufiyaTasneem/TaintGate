
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import psycopg


logger = logging.getLogger(__name__)

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
    """Write security decisions to JSONL and, when configured, PostgreSQL."""

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "decision": decision,
        "reason_code": reason_code,
        "reason": reason,
        "sources": sources or [],
    }

    # Keep the local JSONL log as a fallback and compatibility layer.
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

    # PostgreSQL is optional for tests and local JSONL-only operation.
    database_url = os.getenv("TAINTGATE_DATABASE_URL")
    if not database_url:
        return

    try:
        with psycopg.connect(database_url, connect_timeout=3) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO audit_decisions (
                        timestamp,
                        tool,
                        decision,
                        reason_code,
                        reason,
                        sources
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        entry["timestamp"],
                        entry["tool"],
                        entry["decision"],
                        entry["reason_code"],
                        entry["reason"],
                        json.dumps(entry["sources"]),
                    ),
                )
    except Exception:
        # Do not silently pretend the database write succeeded.
        # JSONL remains available if PostgreSQL is temporarily unavailable.
        logger.exception(
            "PostgreSQL audit write failed; JSONL entry was retained."
        )
