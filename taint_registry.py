
from dataclasses import dataclass, field
from uuid import uuid4
from weakref import WeakKeyDictionary
from threading import RLock
import string


@dataclass
class TaintedData:
    value: str
    source: str
    trusted: bool = False
    taint_id: str = field(default_factory=lambda: str(uuid4()))
    sources: list[str] = field(default_factory=list)


def normalize(value: str) -> str:
    """Normalize case, punctuation, and whitespace for comparison."""
    value = value.lower()
    value = value.translate(str.maketrans("", "", string.punctuation))
    return " ".join(value.split())


class TaintRegistry:
    """Stores untrusted data and provenance for one registry scope."""

    def __init__(self, values=None):
        self.values = values if values is not None else {}
        self._lock = RLock()

    def _add_record(self, value: str, source: str) -> TaintedData:
        existing = self.values.get(value)

        if existing is not None:
            if source not in existing.sources:
                existing.sources.append(source)
            return existing

        record = TaintedData(
            value=value,
            source=source,
            sources=[source],
        )
        self.values[value] = record
        return record

    def register_untrusted(self, value: str, source: str) -> TaintedData:
        if not normalize(value):
            return TaintedData(
                value=value,
                source=source,
                sources=[source],
            )

        with self._lock:
            record = self._add_record(value, source)

            for line in value.splitlines():
                if normalize(line):
                    self._add_record(line, source)

            return record

    def find_tainted_sources(self, candidate: str) -> list[TaintedData]:
        candidate_normalized = normalize(candidate)

        if not candidate_normalized:
            return []

        candidate_words = candidate_normalized.split()
        matches = {}

        with self._lock:
            for original, record in self.values.items():
                key = normalize(original)

                if not key:
                    continue

                if f" {key} " in f" {candidate_normalized} ":
                    matches[record.taint_id] = record
                    continue

                key_words = key.split()

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

    def contains_tainted_data(self, candidate: str) -> bool:
        return bool(self.find_tainted_sources(candidate))


# Backward-compatible global registry.
# Existing tests and direct callers continue using this dictionary.
TAINTED_VALUES: dict[str, TaintedData] = {}
_global_registry = TaintRegistry(TAINTED_VALUES)

# Runtime registries are isolated by MCP session.
_session_registries = WeakKeyDictionary()
_session_registries_lock = RLock()


def get_global_registry() -> TaintRegistry:
    return _global_registry


def get_session_registry(session) -> TaintRegistry:
    """Return the same isolated registry for repeated calls in one session."""
    with _session_registries_lock:
        registry = _session_registries.get(session)

        if registry is None:
            registry = TaintRegistry()
            _session_registries[session] = registry

        return registry


# Backward-compatible global functions.
def register_untrusted(value: str, source: str) -> TaintedData:
    return _global_registry.register_untrusted(value, source)


def find_tainted_sources(candidate: str) -> list[TaintedData]:
    return _global_registry.find_tainted_sources(candidate)


def contains_tainted_data(candidate: str) -> bool:
    return _global_registry.contains_tainted_data(candidate)
