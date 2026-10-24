
import hashlib
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

import psycopg
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent.parent
JSONL_FILE = ROOT / "logs" / "decisions.jsonl"


def timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value)


def main() -> None:
    load_dotenv(ROOT / ".env")

    database_url = os.getenv("TAINTGATE_DATABASE_URL")
    if not database_url:
        raise RuntimeError("TAINTGATE_DATABASE_URL is not configured.")

    if not JSONL_FILE.exists():
        raise FileNotFoundError(f"Audit log not found: {JSONL_FILE}")

    entries = []
    with JSONL_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}; migration stopped."
                ) from exc

            if not isinstance(entry, dict):
                raise ValueError(
                    f"Line {line_number} is not a JSON object; migration stopped."
                )

            for field in ("timestamp", "tool", "decision", "reason"):
                if field not in entry:
                    raise ValueError(
                        f"Line {line_number} is missing {field!r}; migration stopped."
                    )

            entries.append(entry)

    # Give repeated identical lines occurrence-specific keys.
    occurrences = Counter()
    prepared = []

    for entry in entries:
        canonical = json.dumps(
            entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        occurrence_key = (canonical, occurrences[canonical])
        occurrences[canonical] += 1

        migration_key = hashlib.sha256(
            f"{canonical}\noccurrence:{occurrence_key[1]}".encode("utf-8")
        ).hexdigest()

        decision = entry.get("decision", "UNKNOWN")
        if decision == "ALLOW":
            decision = "ALLOWED"

        sources = entry.get("sources", [])
        if not isinstance(sources, list):
            sources = []

        prepared.append(
            (
                migration_key,
                timestamp_value(entry["timestamp"]),
                str(entry["tool"]),
                str(decision),
                str(entry.get("reason_code", "GENERAL")),
                str(entry["reason"]),
                json.dumps(sources),
            )
        )

    print(f"JSONL records validated: {len(prepared)}")
    print("No source files will be modified.")
    confirm = input("Type MIGRATE to import these records: ")
    if confirm != "MIGRATE":
        print("Cancelled; no records imported.")
        return

    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:

            inserted = 0
            for row in prepared:
                cursor.execute(
                    """
                    INSERT INTO audit_decisions (
                        migration_key, timestamp, tool, decision,
                        reason_code, reason, sources
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (migration_key)
                        WHERE migration_key IS NOT NULL
                    DO NOTHING
                    """,
                    row,
                )
                inserted += cursor.rowcount

    print(f"Migration complete. New rows imported: {inserted}")
    print(f"Rows skipped because already imported: {len(prepared) - inserted}")


if __name__ == "__main__":
    main()
