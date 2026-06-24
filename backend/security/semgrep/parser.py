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

            code_snippet=extract_code_snippet(
                result
            ),
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