from .converters import trivy_findings_to_records
from .models import TrivyAnalysisResult
from .parser import build_statistics, parse_trivy_results
from .runner import run_trivy


class TrivyService:
    """
    Main entrypoint for Trivy dependency (SCA) scanning. Mirrors
    security/semgrep/service.py's SemgrepService shape so main.py can
    call both scanners the same way.
    """

    def analyze_repository(self, repo_path: str) -> TrivyAnalysisResult:
        raw_output = run_trivy(repo_path)

        findings = parse_trivy_results(raw_output)

        statistics = build_statistics(findings)

        return TrivyAnalysisResult(
            findings=findings,
            total_findings=statistics["total"],
            critical_count=statistics["critical"],
            high_count=statistics["high"],
            medium_count=statistics["medium"],
            low_count=statistics["low"],
        )

    def analyze_and_convert(
        self,
        repo_id: str,
        repo_path: str,
    ) -> dict:
        """
        Returns findings already converted into the existing database
        schema - same return shape as SemgrepService.analyze_and_convert
        (minus owasp_context/categories, which are Semgrep-RAG-specific
        and not applicable here).
        """

        analysis = self.analyze_repository(repo_path)

        records = trivy_findings_to_records(repo_id, analysis.findings)

        return {
            "records": records,
            "total_findings": analysis.total_findings,
            "critical_count": analysis.critical_count,
            "high_count": analysis.high_count,
            "medium_count": analysis.medium_count,
            "low_count": analysis.low_count,
        }