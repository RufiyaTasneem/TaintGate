import copy

import pytest

from taint_registry import TAINTED_VALUES


@pytest.fixture(autouse=True)
def isolate_taint_registry():
    """Restore shared taint state after every test."""
    original_state = copy.deepcopy(TAINTED_VALUES)

    yield

    TAINTED_VALUES.clear()
    TAINTED_VALUES.update(original_state)