
from dataclasses import dataclass, field
from uuid import uuid4
import string


@dataclass
class TaintedData:
    value: str
    source: str
    trusted: bool = False
    taint_id: str = field(default_factory=lambda: str(uuid4()))
    sources: list[str] = field(default_factory=list)


# Keys preserve the original text for compatibility with existing tests.
TAINTED_VALUES: dict[str, TaintedData] = {}


def normalize(value: str) -> str:
    """Normalize case, punctuation, and whitespace for comparison."""
    value = value.lower()
    value = value.translate(str.maketrans("", "", string.punctuation))
    return " ".join(value.split())


def _add_record(value: str, source: str) -> TaintedData:
    """Store data under its original text and merge duplicate sources."""
    existing = TAINTED_VALUES.get(value)

    if existing is not None:
        if source not in existing.sources:
            existing.sources.append(source)
        return existing

    record = TaintedData(
        value=value,
        source=source,
        sources=[source],
    )
    TAINTED_VALUES[value] = record
    return record


def register_untrusted(value: str, source: str) -> TaintedData:
    """Register untrusted content and each non-empty original line."""
    if not normalize(value):
        return TaintedData(value=value, source=source, sources=[source])

    record = _add_record(value, source)

    for line in value.splitlines():
        if normalize(line):
            _add_record(line, source)

    return record


def find_tainted_sources(candidate: str) -> list[TaintedData]:
    """Find provenance using normalized content and five-word overlap."""
    candidate_normalized = normalize(candidate)

    if not candidate_normalized:
        return []

    candidate_words = candidate_normalized.split()
    matches: dict[str, TaintedData] = {}

    for original, record in TAINTED_VALUES.items():
        key = normalize(original)

        if not key:
            continue

        # Exact normalized content or a registered phrase within candidate.
        if key in candidate_normalized:
            matches[record.taint_id] = record
            continue

        key_words = key.split()

        # Only substantial partial copies match; short fragments alone do not.
        if len(candidate_words) < 5 or len(key_words) < 5:
            continue

        candidate_windows = {
            " ".join(candidate_words[i:i + 5])
            for i in range(len(candidate_words) - 4)
        }
        key_windows = {
            " ".join(key_words[i:i + 5])
            for i in range(len(key_words) - 4)
        }

        if candidate_windows & key_windows:
            matches[record.taint_id] = record

    return list(matches.values())


def contains_tainted_data(candidate: str) -> bool:
    """Return whether candidate matches registered untrusted content."""
    return bool(find_tainted_sources(candidate))
