import hashlib
from typing import Any, Dict, List
from .models import CodeQLFinding

def codeql_findings_to_records(repo_id: str, findings: List[CodeQLFinding]) -> List[Dict[str, Any]]:
    """
    Convert internal CodeQL findings into standard database records.
    """
    records = []
    for f in findings:
        # Create a unique secret_hash / identifier based on rule + location
        id_str = f"{repo_id}:{f.file_path}:{f.line_number}:{f.rule_id}"
        finding_hash = hashlib.sha256(id_str.encode()).hexdigest()

        record = {
            "repo_id": repo_id,
            "file_path": f.file_path,
            "line_number": f.line_number,
            # We store rule details in secret_type as standard
            "secret_type": f.title,
            "severity": f.severity,
            "snippet": f.message[:120],  # Using message snippet
            "secret_hash": finding_hash,
            "source_type": "codeql",
            "rule_id": f.rule_id,
            "rule_name": f.title,
            "vulnerability_description": f.message,
            "recommendation": "Remediate data flow issues and sanitize user inputs.",
            "cwe": f.cwe,
            "owasp_category": f.owasp_category,
            "code_flow": f.code_flow,
            "precision": f.precision,
            "found_in": "current"
        }
        records.append(record)
    return records
