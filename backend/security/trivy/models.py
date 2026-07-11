from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrivyFinding:
    """
    Internal representation of a single Trivy dependency vulnerability.
    """

    file_path: str
    package_name: str

    vulnerability_id: str

    installed_version: str
    fixed_version: Optional[str]

    severity: str

    source: str = "trivy"

    owasp_category: Optional[str] = None

    vulnerability_description: Optional[str] = None

    recommendation: Optional[str] = None


@dataclass
class TrivyAnalysisResult:
    """
    Final output returned by TrivyService.
    """

    findings: list[TrivyFinding] = field(default_factory=list)

    total_findings: int = 0

    critical_count: int = 0

    high_count: int = 0

    medium_count: int = 0

    low_count: int = 0