
from gateway.policy import check_email_policy


def test_blocked_recipient_is_denied():
    decision = check_email_policy("attacker@example.com")

    assert decision.allowed is False
    assert "blocked" in decision.reason.lower()


def test_recipient_matching_is_case_insensitive():
    decision = check_email_policy("  ATTACKER@EXAMPLE.COM  ")

    assert decision.allowed is False


def test_other_recipient_is_allowed():
    decision = check_email_policy("teammate@example.com")

    assert decision.allowed is True


def test_empty_recipient_is_denied():
    decision = check_email_policy("")

    assert decision.allowed is False
def test_blocked_recipient_with_mixed_case_and_whitespace():
    decision = check_email_policy("  AtTaCkEr@ExAmPlE.CoM  ")

    assert decision.allowed is False


def test_recipient_with_only_whitespace_is_denied():
    decision = check_email_policy("   ")

    assert decision.allowed is False


def test_blocked_recipient_with_trailing_newline_is_denied():
    decision = check_email_policy("attacker@example.com\n")

    assert decision.allowed is False