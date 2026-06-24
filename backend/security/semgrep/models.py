from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SemgrepFinding:
    """
    Internal representation of a Semgrep finding.
    """

    file_path: str
    line_number: int

    rule_id: str
    rule_name: str

    severity: str

    source: str = "semgrep"

    owasp_category: Optional[str] = None

    vulnerability_description: Optional[str] = None

    recommendation: Optional[str] = None

    code_snippet: Optional[str] = None


@dataclass
class SemgrepAnalysisResult:
    """
    Final output returned by SemgrepService.
    """

    findings: list[SemgrepFinding] = field(default_factory=list)

    owasp_categories: list[str] = field(default_factory=list)

    owasp_context: str = ""

    total_findings: int = 0

    critical_count: int = 0

    high_count: int = 0

    medium_count: int = 0

    low_count: int = 0


@dataclass
class RepositoryRiskSummary:
    """
    Risk summary passed to Groq.
    """

    total_findings: int

    critical_count: int

    high_count: int

    medium_count: int

    low_count: int

    owasp_categories: list[str]