
import gc
import weakref

from taint_registry import get_session_registry


class FakeSession:
    pass


def test_same_session_reuses_registry():
    session = FakeSession()

    first = get_session_registry(session)
    second = get_session_registry(session)

    assert first is second


def test_different_sessions_have_isolated_registries():
    session_a = FakeSession()
    session_b = FakeSession()

    registry_a = get_session_registry(session_a)
    registry_b = get_session_registry(session_b)

    registry_a.register_untrusted(
        "CONFIDENTIAL_PROJECT_DATA_123",
        "document_a.txt",
    )

    assert registry_a.find_tainted_sources(
        "CONFIDENTIAL_PROJECT_DATA_123"
    )

    assert not registry_b.find_tainted_sources(
        "CONFIDENTIAL_PROJECT_DATA_123"
    )


def test_session_registry_does_not_contaminate_global_registry():
    from taint_registry import find_tainted_sources, TAINTED_VALUES

    TAINTED_VALUES.clear()

    session = FakeSession()
    registry = get_session_registry(session)

    registry.register_untrusted(
        "SESSION_ONLY_SECRET_456",
        "private_document.txt",
    )

    assert registry.find_tainted_sources("SESSION_ONLY_SECRET_456")
    assert not find_tainted_sources("SESSION_ONLY_SECRET_456")


def test_session_registry_allows_garbage_collection():
    session = FakeSession()
    session_reference = weakref.ref(session)

    registry = get_session_registry(session)
    registry_reference = weakref.ref(registry)

    del registry
    del session
    gc.collect()

    assert session_reference() is None
    assert registry_reference() is None
def test_global_registry_does_not_contaminate_session_registry():
    from taint_registry import register_untrusted

    session = FakeSession()
    registry = get_session_registry(session)

    register_untrusted(
        "GLOBAL_CONFIDENTIAL_DATA_789",
        "global_document.txt",
    )

    assert not registry.find_tainted_sources(
        "GLOBAL_CONFIDENTIAL_DATA_789"
    )