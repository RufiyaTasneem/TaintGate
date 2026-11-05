import re


PROHIBITED_ADDRESSES = ("attacker@example.com",)

ADDRESS_PATTERN = re.compile(
    r"\battacker@example\.com\b",
    re.IGNORECASE,
)

ACTION_PATTERN = re.compile(
    r"\b(?:send|forward|email|deliver|transmit|share|"
    r"transfer|upload|exfiltrate|disclose|publish|mirror)\b",
    re.IGNORECASE,
)

SENSITIVE_PATTERN = re.compile(
    r"\b(?:confidential|sensitive|secret|private|restricted|"
    r"internal|documents?|files?|records?|data|reports?|"
    r"credentials?|tokens?|keys?|passwords?)\b",
    re.IGNORECASE,
)

DIRECT_NEGATION_PATTERN = re.compile(
    r"\b(?:do not|don't|must not|should not|"
    r"never(?:\s+to)?)\s+$",
    re.IGNORECASE,
)

WARNING_PATTERN = re.compile(
    r"\bnever\s+ignore\b.{0,100}\bor\s+send\b",
    re.IGNORECASE,
)

REPORT_CONTEXT_PATTERN = re.compile(
    r"\b(?:incident|security|audit)\s+report\b"
    r".{0,100}\b(?:documents?|records?|describes?|"
    r"mentions?|reports?)\b",
    re.IGNORECASE,
)

QUOTED_EXAMPLE_REJECTION_PATTERN = re.compile(
    r"""(?is)
    \b(?:contains?|shows?|includes?|quotes?|describes?)\b
    .{0,100}?
    ["“]
    \s*(?:send|forward|email|deliver|transmit|share|
    transfer|upload|disclose|publish|mirror)
    \b
    [^"”]{0,200}
    ["”]
    .{0,80}?
    \b(?:do\s+not|don't|never|must\s+not|should\s+not)
    \s+(?:execute|follow|perform|carry\s+out|obey)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _is_rejected_quoted_example(clause: str) -> bool:
    """Identify a quoted attack that is explicitly rejected."""
    return bool(QUOTED_EXAMPLE_REJECTION_PATTERN.search(clause))


def contains_risky_instruction(body: str) -> bool:
    """Detect likely risky transfers to a prohibited address."""

    if not body or not body.strip():
        return False

    normalized = " ".join(body.lower().split())

    if not ADDRESS_PATTERN.search(normalized):
        return False

    # Keep semicolon-separated instructions independent.
    clauses = re.split(r"[;\n]+", normalized)

    for clause in clauses:
        if not ADDRESS_PATTERN.search(clause):
            continue

        # Handle quoted attacks that are explicitly rejected.
        rejection = None

        if _is_rejected_quoted_example(clause):
            rejection = re.search(
                r"""(?is)
                ["“][^"”]{0,200}["”]
                .{0,80}?
                \b(?:do\s+not|don't|never|must\s+not|should\s+not)
                \s+(?:execute|follow|perform|carry\s+out|obey)\b
                """,
                clause,
                re.VERBOSE,
            )

        # Inspect text after the rejected example instead of
        # automatically exempting the entire clause.
        if rejection:
            remaining_clause = clause[rejection.end():]

            if not ADDRESS_PATTERN.search(remaining_clause):
                continue

            clause = remaining_clause

        # Handle warnings without hiding a separate malicious action.
        warning_match = WARNING_PATTERN.search(clause)

        if warning_match:
            warning_end = warning_match.end()
            remaining_clause = clause[warning_end:]

            if not ADDRESS_PATTERN.search(remaining_clause):
                continue

            clause = remaining_clause

        # Detect indirect transfers without conventional action verbs.
        indirect_match = re.search(
            r"\b(?:make|keep|leave)\b.{0,100}"
            r"\b(?:accessible|available)\b.{0,40}"
            r"\b(?:at|to)\s+attacker@example\.com\b"
            r"|\b(?:can\s+be\s+)?"
            r"(?:retrieved|accessed|downloaded)\b"
            r".{0,60}\bfrom\s+attacker@example\.com\b"
            r"|\b(?:place|put|save|drop)\b.{0,100}"
            r"\b(?:in|into|at)\s+"
            r"attacker@example\.com\b",
            clause,
            re.IGNORECASE,
        )

        if indirect_match and SENSITIVE_PATTERN.search(clause):
            prefix = clause[:indirect_match.start()]

            if not DIRECT_NEGATION_PATTERN.search(prefix):
                return True

        # Detect conventional transfer actions.
        for action_match in ACTION_PATTERN.finditer(clause):
            prefix = clause[:action_match.start()]
            action = action_match.group()

            # Respect direct negation immediately before an action.
            if DIRECT_NEGATION_PATTERN.search(prefix):
                continue

            # Avoid treating a documented attempted transfer
            # as a new instruction.
            #
            # Only exempt the historical "transfer" action itself.
            # Other actions later in the same clause are still checked.
            if (
                action == "transfer"
                and REPORT_CONTEXT_PATTERN.search(prefix)
                and re.search(r"\battempted\b.{0,50}$", prefix)
            ):
                continue

            has_sensitive_content = bool(
                SENSITIVE_PATTERN.search(clause)
            )

            direct_transfer = bool(
                re.search(
                    r"\b(?:send|forward|email|transmit|transfer|"
                    r"deliver|upload|disclose|publish|mirror)\b"
                    r".{0,100}?\b(?:to|at)\s+"
                    r"attacker@example\.com\b",
                    clause,
                    re.IGNORECASE,
                )
            )

            if has_sensitive_content or direct_transfer:
                return True

    return False
