from typing import Any, Dict, List

def classify_root_cause(finding: Dict[str, Any]) -> str:
    """
    Determine the root cause category based on finding type, rule ID, and source type.
    """
    source_type = finding.get("source_type") or finding.get("detection_method")
    secret_type = (finding.get("secret_type") or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()

    if source_type in ["pattern", "entropy", "secrets"] or "secret" in secret_type or "key" in secret_type:
        return "Hardcoded Secrets"

    if "sql" in rule_id or "sqli" in rule_id:
        return "Unsafe SQL Construction"

    if "xss" in rule_id or "cross-site-scripting" in rule_id:
        return "Cross-Site Scripting (XSS)"

    if "crypto" in rule_id or "cipher" in rule_id or "hash" in rule_id:
        return "Weak Cryptography"

    if "auth" in rule_id or "jwt" in rule_id or "session" in rule_id:
        return "Missing/Insecure Authentication & Authorization"

    if source_type == "trivy" or "cve" in rule_id:
        return "Vulnerable Dependencies (SCA)"

    return "Code Vulnerability"


def cluster_vulnerabilities(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group findings into root cause clusters and return summary metrics.
    """
    clusters_map: Dict[str, List[Dict[str, Any]]] = {}

    for f in findings:
        root_cause = classify_root_cause(f)
        f["root_cause"] = root_cause
        if root_cause not in clusters_map:
            clusters_map[root_cause] = []
        clusters_map[root_cause].append(f)

    result = []
    for root_cause, group in clusters_map.items():
        # Count unique files affected
        files = set()
        total_occs = 0
        for f in group:
            files.add(f.get("file_path"))
            total_occs += len(f.get("occurrences", [f]))

        result.append({
            "root_cause": root_cause,
            "occurrences_count": total_occs,
            "affected_files_count": len(files),
            "findings_count": len(group)
        })

    return result
