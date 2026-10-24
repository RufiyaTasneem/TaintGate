
from collections import Counter
import json
import logging
import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from psycopg.rows import dict_row


load_dotenv()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="TaintGate Security Dashboard",
    description="Local security decision monitoring API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "logs"
    / "decisions.jsonl"
)


def read_decisions_from_jsonl() -> list[dict]:
    """Read valid audit entries from the local JSONL log."""
    if not LOG_FILE.exists():
        return []

    entries = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                entry = json.loads(line)
                if isinstance(entry, dict):
                    entries.append(entry)
            except json.JSONDecodeError:
                continue

    return entries


def read_decisions_from_db() -> list[dict]:
    """Read audit entries from PostgreSQL."""
    database_url = os.getenv("TAINTGATE_DATABASE_URL")
    if not database_url:
        raise RuntimeError("Database URL is not configured.")

    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT timestamp, tool, decision, reason_code, reason, sources
                FROM audit_decisions
                ORDER BY id ASC
                """
            )
            rows = cursor.fetchall()

    entries = []
    for row in rows:
        entry = dict(row)

        # Match the JSONL API format.
        if entry["timestamp"] is not None:
            entry["timestamp"] = entry["timestamp"].isoformat()

        if not isinstance(entry["sources"], list):
            entry["sources"] = []

        entries.append(entry)

    return entries


def read_decisions() -> list[dict]:
    """Prefer PostgreSQL; fall back to JSONL if unavailable."""
    if os.getenv("TAINTGATE_DATABASE_URL"):
        try:
            return read_decisions_from_db()
        except Exception:
            logger.exception(
                "Dashboard database read failed; falling back to JSONL."
            )

    return read_decisions_from_jsonl()


@app.get("/")
def dashboard_info():
    return {
        "name": "TaintGate Security Dashboard",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/api/summary")
def get_summary():
    entries = read_decisions()
    counts = Counter(
        entry.get("decision", "UNKNOWN")
        for entry in entries
    )

    return {
        "total_decisions": len(entries),
        "allowed": counts["ALLOWED"],
        "blocked": counts["BLOCKED"],
    }


@app.get("/api/decisions")
def get_decisions(limit: int = 50):
    entries = read_decisions()
    limit = max(1, min(limit, 200))

    recent_entries = list(reversed(entries[-limit:]))

    # Normalize older audit entries for dashboard compatibility.
    for entry in recent_entries:
        entry.setdefault("reason_code", "GENERAL")
        entry.setdefault("sources", [])

        if not isinstance(entry["sources"], list):
            entry["sources"] = []

    return recent_entries
