
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass
class TaintedData:
    value: str
    source: str
    trusted: bool = False
    taint_id: str = field(default_factory=lambda: str(uuid4()))


def mark_untrusted(value: str, source: str) -> TaintedData:
    """Label data from an untrusted source."""
    return TaintedData(
        value=value,
        source=source,
        trusted=False,
    )


def is_untrusted(data: TaintedData) -> bool:
    """Return whether data is marked as untrusted."""
    return not data.trusted

# In-memory registry of content returned by untrusted sources.
TAINTED_VALUES: dict[str, TaintedData] = {}



def register_untrusted(value: str, source: str) -> None:
    """Track complete untrusted content and its individual lines."""
    if not value:
        return

    # Track the complete document.
    TAINTED_VALUES[value] = mark_untrusted(value, source)

    # Also track each non-empty line separately.
    for line in value.splitlines():
        line = line.strip()

        if line:
            TAINTED_VALUES[line] = mark_untrusted(line, source)



def contains_tainted_data(candidate: str) -> bool:
    """Check whether candidate contains a previously tracked value."""
    return any(
        value in candidate
        for value in TAINTED_VALUES
        if value
    )

def find_tainted_sources(candidate: str) -> list[TaintedData]:
    """Return unique provenance records matching untrusted content."""
    matches = []
    seen_ids = set()

    for value, record in TAINTED_VALUES.items():
        if value and value in candidate and record.taint_id not in seen_ids:
            matches.append(record)
            seen_ids.add(record.taint_id)

    return matches

