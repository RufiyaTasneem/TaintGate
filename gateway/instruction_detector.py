
import re


PROHIBITED_ADDRESSES = ("attacker@example.com",)

ADDRESS_PATTERN = re.compile(
    r"\battacker@example\.com\b",
    re.IGNORECASE,
)

ACTION_PATTERN = re.compile(
    r"\b(?:send|forward|email|deliver|transmit|share|"
    r"transfer|upload|exfiltrate|disclose)\b",
    re.IGNORECASE,
)

SENSITIVE_PATTERN = re.compile(
    r"\b(?:confidential|sensitive|secret|private|restricted|"
    r"internal|documents?|files?|records?|data|reports?|"
    r"credentials?|tokens?|keys?)\b",
    re.IGNORECASE,
)

DIRECT_NEGATION_PATTERN = re.compile(
    r"\b(?:do not|don't|must not|should not|never)\s+$",
    re.IGNORECASE,
)

WARNING_PATTERN = re.compile(
    r"\bnever\s+ignore\b.{0,100}\bor\s+send\b",
    re.IGNORECASE,
)


def contains_risky_instruction(body: str) -> bool:
    """Detect likely risky transfers to a prohibited address."""
    if not body or not body.strip():
        return False

    normalized = " ".join(body.lower().split())

    if not ADDRESS_PATTERN.search(normalized):
        return False

    # Keep email-address periods intact; split independent clauses.
    clauses = re.split(r"[;!?\n]+", normalized)

    for clause in clauses:
        if not ADDRESS_PATTERN.search(clause):
            continue

        if WARNING_PATTERN.search(clause):
            continue

        for action_match in ACTION_PATTERN.finditer(clause):
            prefix = clause[:action_match.start()]

            if DIRECT_NEGATION_PATTERN.search(prefix):
                continue

            has_sensitive_content = bool(
                SENSITIVE_PATTERN.search(clause)
            )

            direct_transfer = bool(
                re.search(
                    r"\b(?:send|forward|email|transmit|transfer|"
                    r"deliver|upload|disclose)\b"
                    r".{0,100}?\bto\s+"
                    r"attacker@example\.com\b",
                    clause,
                    re.IGNORECASE,
                )
            )

            if has_sensitive_content or direct_transfer:
                return True

    return False
