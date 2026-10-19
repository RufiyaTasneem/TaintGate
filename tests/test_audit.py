
import json

from gateway import audit


def test_log_decision_writes_json_entry(tmp_path, monkeypatch):
    log_file = tmp_path / "decisions.jsonl"
    monkeypatch.setattr(audit, "LOG_FILE", log_file)

    audit.log_decision(
        tool_name="send_test_email",
        decision="BLOCKED",
        reason="Test policy violation.",
    )

    entries = log_file.read_text(encoding="utf-8").splitlines()
    assert len(entries) == 1

    entry = json.loads(entries[0])
    assert entry["tool"] == "send_test_email"
    assert entry["decision"] == "BLOCKED"
    assert entry["reason"] == "Test policy violation."
    assert "timestamp" in entry


def test_log_does_not_include_email_body(tmp_path, monkeypatch):
    log_file = tmp_path / "decisions.jsonl"
    monkeypatch.setattr(audit, "LOG_FILE", log_file)

    secret_body = "PRIVATE_TEST_CONTENT_123"
    audit.log_decision(
        tool_name="send_test_email",
        decision="ALLOWED",
        reason="Checks passed.",
    )

    assert secret_body not in log_file.read_text(encoding="utf-8")

def test_log_decision_includes_reason_code_and_sources(
    tmp_path, monkeypatch
):
    log_file = tmp_path / "decisions.jsonl"
    monkeypatch.setattr(audit, "LOG_FILE", log_file)

    audit.log_decision(
        tool_name="send_test_email",
        decision="BLOCKED",
        reason="Untrusted content detected.",
        reason_code="UNTRUSTED_CONTENT",
        sources=["project_update.txt"],
    )

    entry = json.loads(
        log_file.read_text(encoding="utf-8").splitlines()[0]
    )

    assert entry["reason_code"] == "UNTRUSTED_CONTENT"
    assert entry["sources"] == ["project_update.txt"]


def test_allowed_decision_has_empty_sources(
    tmp_path, monkeypatch
):
    log_file = tmp_path / "decisions.jsonl"
    monkeypatch.setattr(audit, "LOG_FILE", log_file)

    audit.log_decision(
        tool_name="send_test_email",
        decision="ALLOWED",
        reason="All checks passed.",
        reason_code="POLICY_PASSED",
    )

    entry = json.loads(
        log_file.read_text(encoding="utf-8").splitlines()[0]
    )

    assert entry["decision"] == "ALLOWED"
    assert entry["reason_code"] == "POLICY_PASSED"
    assert entry["sources"] == []
