from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class Occurrence(BaseModel):
    file_path: str
    line_number: int
    snippet: str
    found_in: str = "current"
    commit_hash: Optional[str] = None

class ValidatedFinding(BaseModel):
    id: str
    scanner: str  # 'secrets', 'semgrep', 'trivy'
    scanner_rule: str
    status: str  # 'VALIDATED', 'NEEDS_REVIEW', 'REJECTED'
    confidence: int  # 0-100
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    title: str
    description: str
    evidence: str
    code_snippet: str
    file: str
    line: int
    function: Optional[str] = None
    framework: Optional[str] = None
    language: Optional[str] = None
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    capec: Optional[str] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    root_cause: str
    occurrences: List[Occurrence] = []
    recommendation: str

class ValidatedFindingsDataset(BaseModel):
    repo_id: str
    raw_count: int
    validated_count: int
    needs_review_count: int
    rejected_count: int
    security_score: int
    findings: List[ValidatedFinding] = []
    clusters: List[Dict[str, Any]] = []
