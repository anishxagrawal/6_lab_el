from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class CodeQLFinding:
    """
    Internal representation of a CodeQL security finding.
    """
    file_path: str
    line_number: int
    rule_id: str
    title: str
    severity: str
    message: str
    cwe: str
    owasp_category: Optional[str] = None
    code_snippet: Optional[str] = None
    precision: str = "high"
    # code_flow is a list of steps tracing data flow from source to sink:
    # [{"file": str, "line": int, "snippet": str, "label": str}]
    code_flow: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class CodeQLAnalysisResult:
    """
    Final output returned by CodeQLService.
    """
    findings: List[CodeQLFinding] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
