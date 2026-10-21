
from collections import Counter
import json
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI

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


def read_decisions() -> list[dict]:
    """Read valid audit entries from the JSONL log."""
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

