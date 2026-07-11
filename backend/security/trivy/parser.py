from .constants import OWASP_CATEGORY, SEVERITY_MAPPING
from .models import TrivyFinding


def normalize_severity(trivy_severity: str) -> str:
    """
    Convert Trivy severity values into application severity values.
    """

    if not trivy_severity:
        return "MEDIUM"

    return SEVERITY_MAPPING.get(
        trivy_severity.upper(),
        "MEDIUM",
    )


def build_recommendation(
    package_name: str,
    fixed_version: str | None,
) -> str:
    """
    Concrete, actionable recommendation - Trivy already tells us the
    exact fixed version, so (unlike Semgrep's generic per-category
    recommendation) this can name the specific upgrade needed.
    """

    if fixed_version:
        return f"Upgrade {package_name} to version {fixed_version} or later."

    return (
        f"No fixed version is published yet for {package_name}. "
        "Track the advisory and pin to a patched release once available, "
        "or evaluate switching to an alternative package."
    )


def parse_trivy_results(trivy_json: dict) -> list[TrivyFinding]:
    """
    Convert Trivy JSON output into TrivyFinding objects.

    Trivy's top-level "Results" key is entirely absent when no
    lockfiles/manifests were found at all (not the same as "found
    manifests, zero vulnerabilities" - that case still has "Results"
    with an empty/missing "Vulnerabilities" list per result). Either
    way, .get(..., []) handles both without raising.
    """

    findings: list[TrivyFinding] = []

    for result in trivy_json.get("Results", []) or []:
        target = result.get("Target", "")

        for vuln in result.get("Vulnerabilities", []) or []:
            vulnerability_id = vuln.get("VulnerabilityID", "unknown-cve")
            package_name = vuln.get("PkgName", "unknown-package")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion") or None

            severity = normalize_severity(vuln.get("Severity", "MEDIUM"))

            title = vuln.get("Title", "") or (
                f"{vulnerability_id} in {package_name}"
            )

            findings.append(
                TrivyFinding(
                    file_path=target,
                    package_name=package_name,
                    vulnerability_id=vulnerability_id,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                    severity=severity,
                    owasp_category=OWASP_CATEGORY,
                    vulnerability_description=title,
                    recommendation=build_recommendation(
                        package_name,
                        fixed_version,
                    ),
                )
            )

    return findings


def build_statistics(findings: list[TrivyFinding]) -> dict:
    """
    Generate summary statistics - same shape as
    security/semgrep/parser.py's build_statistics, for consistency
    between the two scan summaries surfaced in the /scan response.
    """

    stats = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.severity.upper()

        if severity == "CRITICAL":
            stats["critical"] += 1
        elif severity == "HIGH":
            stats["high"] += 1
        elif severity == "MEDIUM":
            stats["medium"] += 1
        elif severity == "LOW":
            stats["low"] += 1

    return stats