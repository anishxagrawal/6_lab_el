from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

KNOWLEDGE_DIR = BASE_DIR / "knowledge"

SEMGREP_CONFIG = "auto"

# Additional local rule packs merged into every scan alongside the
# registry-based "auto" config. Each path is passed as its own
# --config argument to semgrep, so a missing/renamed file here just
# means that pack is skipped rather than crashing the scan.
CUSTOM_RULE_PATHS = [
    BASE_DIR / "rules" / "crypto_misuse.yml",
    BASE_DIR / "rules" / "frontend_rules.yml",
]

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
    "innerhtml": "A03:2021",
    "xpath-injection": "A03:2021",
    "ldap-injection": "A03:2021",
    "nosql-injection": "A03:2021",

    # Cryptographic Failures
    "hardcoded-secret": "A02:2021",
    "hardcoded-password": "A02:2021",
    "hardcoded-token": "A02:2021",
    "private-key": "A02:2021",
    "weak-crypto": "A02:2021",
    "weak-hash": "A02:2021",
    "hardcoded-iv": "A02:2021",
    "weak-rsa-key-size": "A02:2021",
    "insecure-cipher-mode": "A02:2021",
    "insecure-random-for-security": "A02:2021",
    "insecure-storage": "A02:2021",

    # Authentication Failures
    "jwt": "A07:2021",
    "broken-auth": "A07:2021",
    "missing-auth": "A07:2021",
    "authentication": "A07:2021",

    # Security Misconfiguration
    "debug": "A05:2021",
    "misconfiguration": "A05:2021",
    "cors": "A05:2021",
    "cors-wildcard": "A05:2021",
    "noopener": "A05:2021",

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