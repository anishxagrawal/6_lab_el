from .models import SemgrepFinding


def semgrep_to_finding_record(
    repo_id: str,
    finding: SemgrepFinding,
) -> dict:
    """
    Convert SemgrepFinding into the
    existing findings table format.
    """

    return {
        "repo_id": repo_id,

        "file_path": finding.file_path,

        "line_number": finding.line_number,

        "secret_type": (
            finding.rule_name
        ),

        "severity": finding.severity,

        "snippet": (
            finding.code_snippet
            or ""
        ),

        "secret_hash": (
            f"semgrep::{finding.rule_id}"
        ),

        "cluster_id": None,

        # New fields
        "source_type": "semgrep",

        "rule_id": finding.rule_id,

        "rule_name": finding.rule_name,

        "owasp_category": (
            finding.owasp_category
        ),

        "vulnerability_description": (
            finding.vulnerability_description
        ),

        "recommendation": (
            finding.recommendation
        ),
    }


def semgrep_findings_to_records(
    repo_id: str,
    findings: list[SemgrepFinding],
) -> list[dict]:
    """
    Batch conversion helper.
    """

    return [
        semgrep_to_finding_record(
            repo_id,
            finding,
        )
        for finding in findings
    ]


def merge_findings(
    regex_findings: list[dict],
    semgrep_findings: list[dict],
) -> list[dict]:
    """
    Merge existing secret findings
    with Semgrep vulnerability findings.
    """

    combined = []

    combined.extend(
        regex_findings
    )

    combined.extend(
        semgrep_findings
    )

    return combined


def extract_owasp_categories(
    findings: list[dict],
) -> list[str]:
    """
    Extract unique OWASP categories
    from merged findings.
    """

    categories = set()

    for finding in findings:

        category = finding.get(
            "owasp_category"
        )

        if category:
            categories.add(
                category
            )

    return sorted(
        categories
    )


def count_findings_by_source(
    findings: list[dict],
) -> dict:
    """
    Useful for analytics/dashboard.
    """

    counts = {
        "regex": 0,
        "semgrep": 0,
    }

    for finding in findings:

        source = finding.get(
            "source"
        )

        if source in counts:
            counts[source] += 1

    return counts


def build_scan_summary(
    findings: list[dict],
) -> dict:
    """
    Summary used by dashboard
    and Groq prompt.
    """

    summary = {
        "total_findings": len(
            findings
        ),

        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:

        severity = (
            finding.get(
                "severity",
                "",
            )
            .upper()
        )

        if severity == "CRITICAL":
            summary["critical"] += 1

        elif severity == "HIGH":
            summary["high"] += 1

        elif severity == "MEDIUM":
            summary["medium"] += 1

        elif severity == "LOW":
            summary["low"] += 1

    return summary
