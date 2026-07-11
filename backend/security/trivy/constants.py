from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Trivy's own severity vocabulary already matches the app's
# (CRITICAL/HIGH/MEDIUM/LOW), plus UNKNOWN when no vendor supplied a
# rating. Anything unrecognized falls back to MEDIUM, same convention
# as security/semgrep/constants.py's SEVERITY_MAPPING.
SEVERITY_MAPPING = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "LOW",
}

# Every Trivy dependency finding maps to the same OWASP category -
# there's no per-rule keyword lookup needed like Semgrep's RULE_TO_OWASP,
# since "vulnerable/outdated component" is definitionally what this
# scanner detects.
OWASP_CATEGORY = "A06:2021"