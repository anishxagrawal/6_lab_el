from .converters import (
    build_scan_summary,
    semgrep_findings_to_records,
)

from .models import (
    SemgrepAnalysisResult,
    RepositoryRiskSummary,
)

from .parser import (
    build_statistics,
    extract_categories,
    parse_semgrep_results,
)

from .retriever import (
    retrieve_context_bundle,
)

from .runner import (
    run_semgrep,
)


class SemgrepService:
    """
    Main entrypoint for Semgrep scanning.
    """

    def analyze_repository(
        self,
        repo_path: str,
    ) -> SemgrepAnalysisResult:

        raw_output = run_semgrep(
            repo_path
        )

        findings = parse_semgrep_results(
            raw_output
        )

        categories = extract_categories(
            findings
        )

        retrieval_bundle = (
            retrieve_context_bundle(
                categories
            )
        )

        statistics = (
            build_statistics(
                findings
            )
        )

        return SemgrepAnalysisResult(
            findings=findings,

            owasp_categories=
                categories,

            owasp_context=
                retrieval_bundle[
                    "context"
                ],

            total_findings=
                statistics["total"],

            critical_count=
                statistics["critical"],

            high_count=
                statistics["high"],

            medium_count=
                statistics["medium"],

            low_count=
                statistics["low"],
        )

    def analyze_and_convert(
        self,
        repo_id: str,
        repo_path: str,
    ) -> dict:
        """
        Returns findings already converted
        into the existing database schema.
        """

        analysis = (
            self.analyze_repository(
                repo_path
            )
        )

        records = (
            semgrep_findings_to_records(
                repo_id,
                analysis.findings,
            )
        )

        return {
            "records": records,

            "categories":
                analysis.owasp_categories,

            "owasp_context":
                analysis.owasp_context,

            "total_findings":
                analysis.total_findings,

            "critical_count":
                analysis.critical_count,

            "high_count":
                analysis.high_count,

            "medium_count":
                analysis.medium_count,

            "low_count":
                analysis.low_count,
        }

    def build_risk_summary(
        self,
        analysis: SemgrepAnalysisResult,
    ) -> RepositoryRiskSummary:

        return RepositoryRiskSummary(
            total_findings=
                analysis.total_findings,

            critical_count=
                analysis.critical_count,

            high_count=
                analysis.high_count,

            medium_count=
                analysis.medium_count,

            low_count=
                analysis.low_count,

            owasp_categories=
                analysis.owasp_categories,
        )

    def build_groq_payload(
        self,
        analysis: SemgrepAnalysisResult,
    ) -> dict:
        """
        Payload sent to Groq.
        """

        return {
            "findings": [
                {
                    "rule":
                        finding.rule_name,

                    "severity":
                        finding.severity,

                    "owasp":
                        finding.owasp_category,

                    "file":
                        finding.file_path,

                    "line":
                        finding.line_number,

                    "description":
                        finding.vulnerability_description,
                }
                for finding in analysis.findings
            ],

            "owasp_categories":
                analysis.owasp_categories,

            "owasp_context":
                analysis.owasp_context,

            "statistics": {
                "total":
                    analysis.total_findings,

                "critical":
                    analysis.critical_count,

                "high":
                    analysis.high_count,

                "medium":
                    analysis.medium_count,

                "low":
                    analysis.low_count,
            },
        }

    def calculate_security_score(
        self,
        analysis: SemgrepAnalysisResult,
    ) -> int:
        """
        Simple security score.

        Starts at 100.

        Deducts based on severity.
        """

        score = 100

        score -= (
            analysis.critical_count * 15
        )

        score -= (
            analysis.high_count * 8
        )

        score -= (
            analysis.medium_count * 4
        )

        score -= (
            analysis.low_count * 2
        )

        return max(score, 0)