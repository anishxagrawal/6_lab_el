import uuid
from typing import Any, Dict, List, Tuple
from .filters import is_ignored_finding
from .confidence import calculate_confidence
from .deduplicator import deduplicate_findings
from .clustering import cluster_vulnerabilities, classify_root_cause

# CWE -> (OWASP, ASVS) Mapping (Rule 10)
CWE_MAPPING = {
    "CWE-798": ("A02:2021-Cryptographic Failures", "ASVS-3.2.1"),  # Hardcoded credentials
    "CWE-312": ("A02:2021-Cryptographic Failures", "ASVS-3.3.1"),  # Cleartext storage
    "CWE-89": ("A03:2021-Injection", "ASVS-5.3.4"),                # SQL injection
    "CWE-79": ("A03:2021-Injection", "ASVS-5.1.1"),                # XSS
    "CWE-918": ("A10:2021-Server-Side Request Forgery", "ASVS-12.6.1"), # SSRF
    "CWE-287": ("A07:2021-Identification and Authentication Failures", "ASVS-2.1.1"), # Auth
}


def map_owasp_and_cwe(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Apply Rule 10: Map finding to CWE, OWASP, and ASVS based on secret type / rule ID.
    """
    sec_type = (finding.get("secret_type") or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    source_type = finding.get("source_type") or finding.get("detection_method")

    cwe = "CWE-200"  # Exposure of Sensitive Information
    owasp = "A01:2021-Broken Access Control"
    asvs = "ASVS-1.1.1"

    # Secrets mapping
    if source_type in ["pattern", "entropy", "secrets"] or "secret" in sec_type or "key" in sec_type:
        cwe = "CWE-798"
    # Semgrep rules
    elif "sql" in rule_id or "sqli" in rule_id:
        cwe = "CWE-89"
    elif "xss" in rule_id:
        cwe = "CWE-79"
    elif "ssrf" in rule_id:
        cwe = "CWE-918"
    elif "auth" in rule_id or "jwt" in rule_id:
        cwe = "CWE-287"

    if cwe in CWE_MAPPING:
        owasp, asvs = CWE_MAPPING[cwe]

    return cwe, owasp, asvs


def run_validation_pipeline(
    repo_id: str,
    raw_findings: List[Dict[str, Any]],
    repo_profile: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Filter, score, validate, and cluster repository findings.
    Only validated and needs-review findings are returned as user-facing vulnerabilities.
    """
    validated_list = []
    needs_review_list = []
    rejected_list = []

    for f in raw_findings:
        # Create full finding copy to prevent mutations
        finding = dict(f)
        
        file_path = finding.get("file_path", "")
        snippet = finding.get("snippet") or ""
        secret_value = finding.get("secret_value") or ""

        # Rule 1 & Rule 2 path filtering
        if is_ignored_finding(file_path, snippet, secret_value):
            finding["status"] = "REJECTED"
            finding["confidence"] = 0
            rejected_list.append(finding)
            continue

        # Confidence and Framework checks
        conf_score, status = calculate_confidence(finding, repo_profile)
        finding["confidence"] = conf_score
        finding["status"] = status

        # Rule 10: OWASP & CWE Mapping
        cwe, owasp, asvs = map_owasp_and_cwe(finding)
        finding["cwe"] = cwe
        finding["owasp_category"] = owasp
        finding["asvs"] = asvs

        if status == "VALIDATED":
            validated_list.append(finding)
        elif status == "NEEDS_REVIEW":
            needs_review_list.append(finding)
        else:
            rejected_list.append(finding)

    # Combine VALIDATED and NEEDS_REVIEW for frontend list & deduplication
    displayable_findings = validated_list + needs_review_list

    # Deduplicate findings
    deduped = deduplicate_findings(displayable_findings)

    # Final root cause clustering
    clusters = cluster_vulnerabilities(deduped)

    # Dynamic security score calculation based on VALIDATED findings only
    sec_score = 100
    for f in validated_list:
        sev = str(f.get("severity") or "LOW").upper()
        if sev == "CRITICAL":
            sec_score -= 15
        elif sev == "HIGH":
            sec_score -= 8
        elif sev == "MEDIUM":
            sec_score -= 3
        elif sev == "LOW":
            sec_score -= 1

    sec_score = max(0, min(100, sec_score))

    # Format findings list into standard ValidatedFinding models format
    formatted_findings = []
    for f in deduped:
        formatted_findings.append({
            "id": f.get("id") or str(uuid.uuid4()),
            "scanner": f.get("source_type") or f.get("detection_method") or "secrets",
            "scanner_rule": f.get("rule_id") or f.get("secret_type") or "Vulnerability",
            "status": f.get("status"),
            "confidence": f.get("confidence", 0),
            "severity": f.get("severity"),
            "title": f.get("secret_type") or f.get("rule_name") or "Vulnerability",
            "description": f.get("vulnerability_description") or f.get("snippet") or "",
            "evidence": f.get("file_path") + ":" + str(f.get("line_number", 0)),
            "code_snippet": f.get("snippet") or "",
            "file": f.get("file_path"),
            "line": int(f.get("line_number") or 0),
            "owasp": f.get("owasp_category"),
            "cwe": f.get("cwe"),
            "root_cause": f.get("root_cause", "Code Vulnerability"),
            "occurrences": f.get("occurrences", []),
            "recommendation": f.get("recommendation") or "Remediate exposed credential or update config.",
        })

    return {
        "repo_id": repo_id,
        "raw_count": len(raw_findings),
        "validated_count": len(validated_list),
        "needs_review_count": len(needs_review_list),
        "rejected_count": len(rejected_list),
        "security_score": sec_score,
        "findings": formatted_findings,
        "clusters": clusters,
    }
