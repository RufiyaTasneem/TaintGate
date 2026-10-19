
from dataclasses import dataclass


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


# Mock blocked recipient for our security tests.
BLOCKED_RECIPIENTS = {
    "attacker@example.com",
}



def check_email_policy(recipient: str) -> PolicyDecision:
    """Decide whether a mock email recipient is permitted."""

    normalized_recipient = recipient.strip().lower()

    if not normalized_recipient:
        return PolicyDecision(
            allowed=False,
            reason="Recipient must not be empty.",
        )

    if normalized_recipient in BLOCKED_RECIPIENTS:
        return PolicyDecision(
            allowed=False,
            reason="Recipient is explicitly blocked by policy.",
        )

    return PolicyDecision(
        allowed=True,
        reason="No blocking rule matched.",
    )

