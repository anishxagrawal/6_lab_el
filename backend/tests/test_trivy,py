"""
Tests for the Trivy dependency (SCA) scanning module (Phase 10).

Trivy's vulnerability database has to be downloaded from a container
registry on first run, which most CI/sandboxed environments block by
default (it's not a simple pip/HTTP dependency). Rather than depend on
that being reachable, these tests exercise the parser/converter/service
logic against a captured, realistic Trivy JSON payload -- the same
approach the project already uses for offline-testable modules. A
handful of runner-level tests do use the real `trivy` binary if it's on
PATH, but only for things that don't require the vulnerability DB
(executable discovery, graceful "not installed" fallback).
"""

from __future__ import annotations

import shutil

from security.trivy.constants import OWASP_CATEGORY
from security.trivy.converters import trivy_findings_to_records
from security.trivy.parser import (
    build_recommendation,
    build_statistics,
    normalize_severity,
    parse_trivy_results,
)
from security.trivy.runner import _find_trivy_executable, run_trivy
from security.trivy.service import TrivyService

SAMPLE_TRIVY_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "testrepo",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2015-2296",
                    "PkgName": "requests",
                    "InstalledVersion": "2.6.0",
                    "FixedVersion": "2.6.1",
                    "Title": "python-requests: session fixation vulnerability",
                    "Severity": "HIGH",
                },
                {
                    "VulnerabilityID": "CVE-2019-19844",
                    "PkgName": "django",
                    "InstalledVersion": "2.0.0",
                    "FixedVersion": "2.2.9, 3.0.1",
                    "Title": "django: Django allows account takeover",
                    "Severity": "CRITICAL",
                },
            ],
        },
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.11",
                    "FixedVersion": "4.17.21",
                    "Title": "lodash: command injection",
                    "Severity": "CRITICAL",
                },
            ],
        },
        # A scanned manifest with no vulnerabilities found (real Trivy
        # output includes the result with no "Vulnerabilities" key at
        # all in this case, not an empty list) -- must not raise.
        {
            "Target": "go.sum",
            "Class": "lang-pkgs",
            "Type": "gomod",
        },
        # A non-vulnerability result class (e.g. misconfig scanning),
        # which this project never requests (--scanners vuln only) but
        # the parser should ignore gracefully regardless.
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
        },
    ],
}


class TestNormalizeSeverity:
    def test_maps_known_severities_unchanged(self):
        assert normalize_severity("CRITICAL") == "CRITICAL"
        assert normalize_severity("HIGH") == "HIGH"
        assert normalize_severity("MEDIUM") == "MEDIUM"
        assert normalize_severity("LOW") == "LOW"

    def test_maps_unknown_severity_to_low(self):
        assert normalize_severity("UNKNOWN") == "LOW"

    def test_maps_empty_or_unrecognized_to_medium(self):
        assert normalize_severity("") == "MEDIUM"
        assert normalize_severity("SOMETHING_NEW") == "MEDIUM"

    def test_is_case_insensitive(self):
        assert normalize_severity("critical") == "CRITICAL"


class TestBuildRecommendation:
    def test_names_the_exact_fixed_version(self):
        rec = build_recommendation("requests", "2.6.1")
        assert "requests" in rec
        assert "2.6.1" in rec

    def test_handles_missing_fixed_version(self):
        rec = build_recommendation("some-package", None)
        assert "some-package" in rec
        assert "No fixed version" in rec


class TestParseTrivyResults:
    def test_extracts_all_vulnerabilities_across_targets(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        assert len(findings) == 3

    def test_ignores_targets_with_no_vulnerabilities_key(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        file_paths = [f.file_path for f in findings]
        assert "go.sum" not in file_paths
        assert "Dockerfile" not in file_paths

    def test_every_finding_maps_to_a06(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        assert all(f.owasp_category == OWASP_CATEGORY for f in findings)

    def test_handles_completely_empty_input(self):
        assert parse_trivy_results({}) == []

    def test_handles_missing_results_key(self):
        assert parse_trivy_results({"SchemaVersion": 2}) == []

    def test_field_values_are_correctly_extracted(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        requests_finding = next(f for f in findings if f.package_name == "requests")

        assert requests_finding.vulnerability_id == "CVE-2015-2296"
        assert requests_finding.installed_version == "2.6.0"
        assert requests_finding.fixed_version == "2.6.1"
        assert requests_finding.severity == "HIGH"
        assert requests_finding.file_path == "requirements.txt"


class TestBuildStatistics:
    def test_counts_by_severity(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        stats = build_statistics(findings)

        assert stats["total"] == 3
        assert stats["critical"] == 2
        assert stats["high"] == 1
        assert stats["medium"] == 0
        assert stats["low"] == 0

    def test_empty_findings_list(self):
        stats = build_statistics([])
        assert stats == {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


class TestConverters:
    def test_record_has_expected_shape_and_source_type(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        records = trivy_findings_to_records("repo-123", findings)

        record = next(r for r in records if r["rule_id"] == "CVE-2015-2296")

        assert record["repo_id"] == "repo-123"
        assert record["source_type"] == "trivy"
        assert record["owasp_category"] == "A06:2021"
        assert record["line_number"] == 0
        assert record["snippet"] == "requests==2.6.0"
        assert record["secret_hash"] == "trivy::CVE-2015-2296::requests"
        assert "2.6.1" in record["recommendation"]

    def test_secret_hash_is_unique_per_cve_and_package(self):
        findings = parse_trivy_results(SAMPLE_TRIVY_JSON)
        records = trivy_findings_to_records("repo-123", findings)

        hashes = [r["secret_hash"] for r in records]
        assert len(hashes) == len(set(hashes))


class TestTrivyServiceWithFakeRunner(object):
    """
    Exercises the full TrivyService.analyze_repository/analyze_and_convert
    path by monkeypatching run_trivy, so it doesn't depend on the real
    binary or a reachable vulnerability database.
    """

    def test_analyze_repository_returns_populated_result(self, monkeypatch):
        import security.trivy.service as service_module

        monkeypatch.setattr(
            service_module, "run_trivy", lambda repo_path: SAMPLE_TRIVY_JSON
        )

        result = TrivyService().analyze_repository("/fake/path")

        assert result.total_findings == 3
        assert result.critical_count == 2
        assert result.high_count == 1

    def test_analyze_and_convert_returns_db_ready_records(self, monkeypatch):
        import security.trivy.service as service_module

        monkeypatch.setattr(
            service_module, "run_trivy", lambda repo_path: SAMPLE_TRIVY_JSON
        )

        result = TrivyService().analyze_and_convert(
            repo_id="repo-abc", repo_path="/fake/path"
        )

        assert result["total_findings"] == 3
        assert len(result["records"]) == 3
        assert all(r["repo_id"] == "repo-abc" for r in result["records"])


class TestRunnerExecutableDiscovery:
    def test_returns_none_when_no_binary_on_path(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name: None)
        monkeypatch.delenv("TRIVY_PATH", raising=False)

        assert _find_trivy_executable() is None

    def test_run_trivy_returns_empty_results_when_not_installed(self, monkeypatch):
        import security.trivy.runner as runner_module

        monkeypatch.setattr(runner_module, "_find_trivy_executable", lambda: None)

        result = run_trivy("/some/path")

        assert result == {"Results": []}

    def test_finds_real_binary_if_present_on_this_machine(self):
        # Purely informational / environment-dependent - doesn't assert
        # a specific outcome, just that calling it doesn't raise.
        _find_trivy_executable()