
from taint_registry import (
    TaintedData,
    TAINTED_VALUES,
    normalize,
    register_untrusted,
    find_tainted_sources,
    contains_tainted_data,
)


def mark_untrusted(value: str, source: str = "unknown") -> TaintedData:
    """Register untrusted data and return its provenance record."""
    return register_untrusted(value, source)


def is_untrusted(value: str | TaintedData) -> bool:
    """Check whether a value or provenance record is untrusted."""
    if isinstance(value, TaintedData):
        return not value.trusted

    return contains_tainted_data(value)


__all__ = [
    "TaintedData",
    "TAINTED_VALUES",
    "normalize",
    "register_untrusted",
    "find_tainted_sources",
    "contains_tainted_data",
    "mark_untrusted",
    "is_untrusted",
]
