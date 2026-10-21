
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass
class TaintedData:
    value: str
    source: str
    trusted: bool = False
    taint_id: str = field(default_factory=lambda: str(uuid4()))
    sources: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.sources:
            self.sources = [self.source]


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


# Maps each tracked text value to its provenance record.
TAINTED_VALUES: dict[str, TaintedData] = {}


def register_untrusted(value: str, source: str) -> None:
    """Track untrusted content and retain all known source documents."""
    if not value or not value.strip():
        return

    candidates = [value]
    candidates.extend(
        line.strip()
        for line in value.splitlines()
        if line.strip()
    )

    for candidate in candidates:
        record = TAINTED_VALUES.get(candidate)

        if record is None:
            TAINTED_VALUES[candidate] = mark_untrusted(
                candidate,
                source,
            )
        elif source not in record.sources:
            record.sources.append(source)


def contains_tainted_data(candidate: str) -> bool:
    """Check whether candidate contains tracked untrusted content."""
    if not candidate:
        return False

    return any(
        value in candidate
        for value in TAINTED_VALUES
        if value
    )



def find_tainted_sources(candidate: str) -> list[TaintedData]:
    """Find exact or substantial partial matches to tracked untrusted text."""
    if not candidate or not candidate.strip():
        return []

    matches = []
    seen_ids = set()
    normalized_candidate = " ".join(candidate.lower().split())

    tracked_values = sorted(
        TAINTED_VALUES.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    )

    for value, record in tracked_values:
        if not value:
            continue

        normalized_value = " ".join(value.lower().split())

        # Preserve the original exact-substring detection.
        if normalized_value in normalized_candidate:
            if record.taint_id not in seen_ids:
                matches.append(record)
                seen_ids.add(record.taint_id)
            continue

        # Also detect a copied sequence of at least 6 words.
        # Also detect a copied sequence of at least 5 words.
        words = normalized_value.split()
        candidate_words = normalized_candidate.split()
        window_size = 5

        if len(words) < window_size or len(candidate_words) < window_size:
            continue

        for start in range(len(words) - window_size + 1):
            phrase = " ".join(words[start:start + window_size])

            for candidate_start in range(
                len(candidate_words) - window_size + 1
            ):
                candidate_phrase = " ".join(
                    candidate_words[
                        candidate_start:candidate_start + window_size
                    ]
                )

                if phrase == candidate_phrase:
                    if record.taint_id not in seen_ids:
                        matches.append(record)
                        seen_ids.add(record.taint_id)
                    break

            if record.taint_id in seen_ids:
                break

    return matches

