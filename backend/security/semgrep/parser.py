from .constants import SEVERITY_MAPPING
from .mapper import map_to_owasp
from .models import SemgrepFinding


def normalize_severity(
    semgrep_severity: str,
) -> str:
    """
    Convert Semgrep severity values
    into application severity values.
    """

    if not semgrep_severity:
        return "MEDIUM"

    semgrep_severity = (
        semgrep_severity.upper()
    )

    return SEVERITY_MAPPING.get(
        semgrep_severity,
        "MEDIUM",
    )


def extract_code_snippet(
    result: dict,
) -> str:
    """
    Extract vulnerable code snippet.
    """

    extra = result.get("extra", {})

    lines = extra.get(
        "lines",
        ""
    )

    if isinstance(lines, str):
        return lines.strip()

    return ""


def extract_message(
    result: dict,
) -> str:
    """
    Human-readable vulnerability message.
    """

    return (
        result.get("extra", {})
        .get("message", "")
        .strip()
    )


def build_recommendation(
    owasp_category: str | None,
) -> str:
    """
    Generic recommendation generator.

    This is the static, always-present fallback shown for every finding.
    Phase 6 (ai/remediation.py) additionally attaches a per-finding,
    AI-generated `ai_suggested_fix` to a bounded top-10 subset of
    CRITICAL/HIGH Semgrep findings; when present it's the more specific
    suggestion to show, with this generic `recommendation` remaining as
    the fallback for every other finding (or if the Groq call fails/isn't
    configured).
    """

    recommendations = {
        "A01:2021":
            "Implement authorization checks and enforce least privilege.",

        "A02:2021":
            "Remove hardcoded secrets and use a secure secrets manager.",

        "A03:2021":
            "Validate input and use parameterized APIs.",

        "A04:2021":
            "Review application design and threat models.",

        "A05:2021":
            "Harden configuration and disable unsafe defaults.",

        "A06:2021":
            "Update dependencies and remove vulnerable components.",

        "A07:2021":
            "Strengthen authentication and session management.",

        "A08:2021":
            "Verify integrity of software and data flows.",

        "A09:2021":
            "Improve logging, monitoring, and alerting.",

        "A10:2021":
            "Restrict outbound requests and validate URLs.",
    }

    return recommendations.get(
        owasp_category,
        "Review and remediate the issue."
    )


def parse_semgrep_results(
    semgrep_json: dict,
) -> list[SemgrepFinding]:
    """
    Convert Semgrep JSON output into
    SemgrepFinding objects.
    """

    findings = []

    for result in semgrep_json.get(
        "results",
        [],
    ):

        rule_id = result.get(
            "check_id",
            "unknown-rule",
        )

        code_snippet = extract_code_snippet(result)
        is_secret_rule = any(x in rule_id.lower() for x in ["secret", "password", "token", "jwt", "key", "credential"])
        if is_secret_rule:
            snippet_lower = code_snippet.lower()
            false_positive_indicators = [
                "graphene.string", "graphene.field", "graphene.argument",
                "charfield", "textfield", "integerfield", "booleanfield",
                "schema.string", "schema.char", "=models.", "=schema.",
                "serializer", "field(", "string(", "types.string",
                "dynamicfield", "db.string", "db.varchar"
            ]
            if any(indicator in snippet_lower for indicator in false_positive_indicators):
                continue

        message = extract_message(
            result
        )

        severity = normalize_severity(
            result.get(
                "extra",
                {},
            ).get(
                "severity",
                "MEDIUM",
            )
        )

        owasp_category = map_to_owasp(
            rule_id
        )

        finding = SemgrepFinding(
            file_path=result.get(
                "path",
                "",
            ),

            line_number=result.get(
                "start",
                {},
            ).get(
                "line",
                0,
            ),

            rule_id=rule_id,

            rule_name=message
            if message
            else rule_id,

            severity=severity,

            owasp_category=owasp_category,

            vulnerability_description=message,

            recommendation=build_recommendation(
                owasp_category
            ),

            code_snippet=code_snippet,
        )

        findings.append(
            finding
        )

    return findings


def extract_categories(
    findings: list[SemgrepFinding],
) -> list[str]:
    """
    Extract unique OWASP categories.
    """

    return sorted(
        {
            finding.owasp_category
            for finding in findings
            if finding.owasp_category
        }
    )


def build_statistics(
    findings: list[SemgrepFinding],
) -> dict:
    """
    Generate summary statistics.
    """

    stats = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:

        severity = (
            finding.severity.upper()
        )

        if severity == "CRITICAL":
            stats["critical"] += 1

        elif severity == "HIGH":
            stats["high"] += 1

        elif severity == "MEDIUM":
            stats["medium"] += 1

        elif severity == "LOW":
            stats["low"] += 1

    return stats