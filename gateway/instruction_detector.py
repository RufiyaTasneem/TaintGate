import re


PROHIBITED_ADDRESSES = (
    "attacker@example.com",
)

ACTION_PATTERN = re.compile(
    r"\b(?:send|forward|email|deliver|transmit|share|"
    r"transfer|upload|exfiltrate|disclose)\b",
    re.IGNORECASE,
)

SENSITIVE_PATTERN = re.compile(
    r"\b(?:confidential|sensitive|secret|private|"
    r"restricted|internal)\b|"
    r"\b(?:documents?|files?|records?|data|reports?|"
    r"credentials?|tokens?|keys?)\b",
    re.IGNORECASE,
)

BENIGN_CONTEXT_PATTERN = re.compile(
    r"\b(?:do not|don't|never|avoid|prevent|prohibit|"
    r"blocked|blocking|warning|warn|detect|detected|"
    r"security review|test logs|found in|example of|"
    r"quoted example|should not|must not|not to)\b",
    re.IGNORECASE,
)


def contains_risky_instruction(body: str) -> bool:
    """Detect likely risky instructions targeting a prohibited address."""
    if not body or not body.strip():
        return False

    normalized = " ".join(body.lower().split())

    if not any(
        address in normalized
        for address in PROHIBITED_ADDRESSES
    ):
        return False

    # Preserve legitimate warnings and security discussions.
    if BENIGN_CONTEXT_PATTERN.search(normalized):
        return False

    # A direct action to the prohibited address is sufficient.
    # Longer transfers of sensitive data are also detected.
    has_action = bool(ACTION_PATTERN.search(normalized))
    has_sensitive_content = bool(
        SENSITIVE_PATTERN.search(normalized)
    )

    return has_action and (
        has_sensitive_content
        or re.search(
            r"\b(?:send|forward)\s+"
            r"(?:(?:it|this|that)\s+)?to\s+"
            r"attacker@example\.com\b",
            normalized,
        )
        is not None
    )