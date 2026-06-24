from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

KNOWLEDGE_DIR = BASE_DIR / "knowledge"

SEMGREP_CONFIG = "auto"

SEVERITY_MAPPING = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
    "LOW": "LOW",
}

RULE_TO_OWASP = {
    # Injection
    "sql-injection": "A03:2021",
    "command-injection": "A03:2021",
    "xss": "A03:2021",
    "xpath-injection": "A03:2021",
    "ldap-injection": "A03:2021",
    "nosql-injection": "A03:2021",

    # Cryptographic Failures
    "hardcoded-secret": "A02:2021",
    "hardcoded-password": "A02:2021",
    "hardcoded-token": "A02:2021",
    "private-key": "A02:2021",
    "weak-crypto": "A02:2021",

    # Authentication Failures
    "jwt": "A07:2021",
    "broken-auth": "A07:2021",
    "missing-auth": "A07:2021",
    "authentication": "A07:2021",

    # Security Misconfiguration
    "debug": "A05:2021",
    "misconfiguration": "A05:2021",
    "cors": "A05:2021",

    # SSRF
    "ssrf": "A10:2021",

    # Integrity Failures
    "deserialization": "A08:2021",
    "pickle": "A08:2021",

    # Logging Failures
    "logging": "A09:2021",

    # Access Control
    "access-control": "A01:2021",
    "idor": "A01:2021",
}