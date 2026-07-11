from .models import TrivyFinding


def trivy_to_finding_record(
    repo_id: str,
    finding: TrivyFinding,
) -> dict:
    """
    Convert a TrivyFinding into the existing findings table format -
    same target schema as security/semgrep/converters.py's
    semgrep_to_finding_record, so Trivy findings can be concatenated
    into the same all_findings list and upserted in one call.

    Dependency vulnerabilities aren't tied to a specific line, unlike
    secret/Semgrep findings, so line_number is 0 rather than omitted
    (keeps the column non-null across all finding types).
    """

    return {
        "repo_id": repo_id,
        "file_path": finding.file_path,
        "line_number": 0,
        "secret_type": finding.vulnerability_id,
        "severity": finding.severity,
        "snippet": (
            f"{finding.package_name}=={finding.installed_version}"
        ),
        "secret_hash": (
            f"trivy::{finding.vulnerability_id}::{finding.package_name}"
        ),
        "cluster_id": None,
        "source_type": "trivy",
        "rule_id": finding.vulnerability_id,
        "rule_name": f"{finding.package_name}@{finding.installed_version}",
        "owasp_category": finding.owasp_category,
        "vulnerability_description": finding.vulnerability_description,
        "recommendation": finding.recommendation,
    }


def trivy_findings_to_records(
    repo_id: str,
    findings: list[TrivyFinding],
) -> list[dict]:
    """
    Batch conversion helper.
    """

    return [
        trivy_to_finding_record(repo_id, finding)
        for finding in findings
    ]