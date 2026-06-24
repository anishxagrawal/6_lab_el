from .constants import RULE_TO_OWASP


def map_to_owasp(rule_id: str) -> str | None:
    """
    Convert Semgrep rule IDs into OWASP Top 10 categories.

    Example:
        python.lang.security.audit.sql-injection
        -> A03:2021

        generic.secrets.security.detected-private-key
        -> A02:2021
    """

    if not rule_id:
        return None

    rule_id = rule_id.lower()

    for keyword, category in RULE_TO_OWASP.items():
        if keyword in rule_id:
            return category

    return None


OWASP_METADATA = {
    "A01:2021": {
        "name": "Broken Access Control",
        "severity": "HIGH",
    },

    "A02:2021": {
        "name": "Cryptographic Failures",
        "severity": "HIGH",
    },

    "A03:2021": {
        "name": "Injection",
        "severity": "CRITICAL",
    },

    "A04:2021": {
        "name": "Insecure Design",
        "severity": "MEDIUM",
    },

    "A05:2021": {
        "name": "Security Misconfiguration",
        "severity": "HIGH",
    },

    "A06:2021": {
        "name": "Vulnerable Components",
        "severity": "HIGH",
    },

    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "severity": "HIGH",
    },

    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "severity": "HIGH",
    },

    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "severity": "MEDIUM",
    },

    "A10:2021": {
        "name": "Server-Side Request Forgery",
        "severity": "HIGH",
    },
}


def get_owasp_name(category: str) -> str:
    """
    A03:2021 -> Injection
    """

    metadata = OWASP_METADATA.get(category)

    if not metadata:
        return category

    return metadata["name"]


def get_owasp_severity(category: str) -> str:
    """
    Returns recommended severity for category.
    """

    metadata = OWASP_METADATA.get(category)

    if not metadata:
        return "MEDIUM"

    return metadata["severity"]


def build_owasp_summary(
    categories: list[str],
) -> list[dict]:
    """
    Converts:

        ["A03:2021", "A10:2021"]

    Into:

        [
            {
                "id": "A03:2021",
                "name": "Injection"
            },
            {
                "id": "A10:2021",
                "name": "Server-Side Request Forgery"
            }
        ]
    """

    summary = []

    for category in sorted(set(categories)):
        summary.append(
            {
                "id": category,
                "name": get_owasp_name(category),
                "severity": get_owasp_severity(category),
            }
        )

    return summary