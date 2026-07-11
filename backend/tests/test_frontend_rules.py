"""
Tests for the custom frontend-vulnerability Semgrep rule pack
(security/semgrep/rules/frontend_rules.yml).

Same approach as test_crypto_misuse_rules.py: invoke Semgrep directly
against the rule file (not the registry "auto" config) so these tests
don't need network access to semgrep.dev.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security.semgrep import runner as runner_module
from security.semgrep.constants import BASE_DIR
from security.semgrep.service import SemgrepService

RULES_PATH = BASE_DIR / "rules" / "frontend_rules.yml"

SEMGREP_AVAILABLE = shutil.which("semgrep") is not None or shutil.which("pysemgrep") is not None

pytestmark = pytest.mark.skipif(
    not SEMGREP_AVAILABLE,
    reason="semgrep executable not found on PATH",
)


def _run_frontend_rules_only(file_path: Path) -> dict:
    """
    Run only the frontend rule pack (no registry "auto" config) against
    a single file, and return the parsed Semgrep JSON.
    """

    command = [
        shutil.which("semgrep") or shutil.which("pysemgrep"),
        "scan",
        "--config",
        str(RULES_PATH),
        "--json",
        str(file_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode in (0, 1), result.stderr

    return json.loads(result.stdout)


def _check_ids(semgrep_json: dict) -> list[str]:
    """
    Normalize away Semgrep's local-config directory-namespace prefix
    (e.g. "security.semgrep.rules.frontend-dom-xss-innerhtml" ->
    "frontend-dom-xss-innerhtml"). See test_crypto_misuse_rules.py for
    the full explanation of why this prefix appears.
    """

    return [r["check_id"].rsplit(".", 1)[-1] for r in semgrep_json.get("results", [])]


class TestRulePackIsValid:
    def test_rule_file_exists(self):
        assert RULES_PATH.exists()

    def test_semgrep_validate_reports_no_errors(self):
        command = [
            shutil.which("semgrep") or shutil.which("pysemgrep"),
            "--validate",
            "--config",
            str(RULES_PATH),
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=60)

        assert "0 configuration error" in (result.stdout + result.stderr)


class TestDomXssDetection:
    def test_detects_innerhtml_assignment(self, tmp_path):
        sample = tmp_path / "bad.jsx"
        sample.write_text(
            "document.getElementById('out').innerHTML = userComment;\n"
        )

        assert "frontend-dom-xss-innerhtml" in _check_ids(_run_frontend_rules_only(sample))

    def test_detects_document_write(self, tmp_path):
        sample = tmp_path / "bad.jsx"
        sample.write_text("document.write(userInput);\n")

        assert "frontend-dom-xss-innerhtml" in _check_ids(_run_frontend_rules_only(sample))

    def test_allows_textcontent(self, tmp_path):
        sample = tmp_path / "good.jsx"
        sample.write_text(
            "document.getElementById('out').textContent = userComment;\n"
        )

        assert "frontend-dom-xss-innerhtml" not in _check_ids(_run_frontend_rules_only(sample))


class TestDangerouslySetInnerHtmlDetection:
    def test_detects_dangerously_set_inner_html(self, tmp_path):
        sample = tmp_path / "bad.jsx"
        sample.write_text(
            "function Comment(props) {\n"
            "  return <div dangerouslySetInnerHTML={{__html: props.userComment}} />;\n"
            "}\n"
        )

        assert "frontend-react-dangerously-set-innerhtml" in _check_ids(
            _run_frontend_rules_only(sample)
        )

    def test_allows_plain_jsx_children(self, tmp_path):
        sample = tmp_path / "good.jsx"
        sample.write_text(
            "function Comment(props) {\n"
            "  return <div>{props.userComment}</div>;\n"
            "}\n"
        )

        assert "frontend-react-dangerously-set-innerhtml" not in _check_ids(
            _run_frontend_rules_only(sample)
        )


class TestInsecureStorageDetection:
    def test_detects_token_in_local_storage(self, tmp_path):
        sample = tmp_path / "bad.js"
        sample.write_text("localStorage.setItem('authToken', token);\n")

        assert "frontend-insecure-storage-of-token" in _check_ids(
            _run_frontend_rules_only(sample)
        )

    def test_detects_api_key_in_session_storage(self, tmp_path):
        sample = tmp_path / "bad.js"
        sample.write_text("sessionStorage.setItem('apiKey', key);\n")

        assert "frontend-insecure-storage-of-token" in _check_ids(
            _run_frontend_rules_only(sample)
        )

    def test_allows_non_sensitive_keys(self, tmp_path):
        sample = tmp_path / "good.js"
        sample.write_text("localStorage.setItem('theme', 'dark');\n")

        assert "frontend-insecure-storage-of-token" not in _check_ids(
            _run_frontend_rules_only(sample)
        )


class TestCorsWildcardDetection:
    def test_detects_wildcard_origin_with_credentials(self, tmp_path):
        sample = tmp_path / "bad.py"
        sample.write_text(
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=['*'],\n"
            "    allow_credentials=True,\n"
            ")\n"
        )

        assert "frontend-cors-wildcard-with-credentials" in _check_ids(
            _run_frontend_rules_only(sample)
        )

    def test_allows_explicit_origin_allowlist(self, tmp_path):
        sample = tmp_path / "good.py"
        sample.write_text(
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=['https://example.com'],\n"
            "    allow_credentials=True,\n"
            ")\n"
        )

        assert "frontend-cors-wildcard-with-credentials" not in _check_ids(
            _run_frontend_rules_only(sample)
        )


class TestTargetBlankNoopenerDetection:
    def test_detects_target_blank_without_noopener(self, tmp_path):
        sample = tmp_path / "bad.html"
        sample.write_text(
            '<a href="https://external.example.com" target="_blank">Link</a>\n'
        )

        assert "frontend-target-blank-missing-noopener" in _check_ids(
            _run_frontend_rules_only(sample)
        )

    def test_allows_target_blank_with_noopener(self, tmp_path):
        sample = tmp_path / "good.html"
        sample.write_text(
            '<a href="https://ok.example.com" target="_blank" '
            'rel="noopener noreferrer">Link</a>\n'
        )

        assert "frontend-target-blank-missing-noopener" not in _check_ids(
            _run_frontend_rules_only(sample)
        )


class TestOwaspMapping:
    def test_frontend_rule_ids_map_to_expected_owasp_categories(self):
        from security.semgrep.mapper import map_to_owasp

        expected = {
            "frontend-dom-xss-innerhtml": "A03:2021",
            "frontend-react-dangerously-set-innerhtml": "A03:2021",
            "frontend-insecure-storage-of-token": "A02:2021",
            "frontend-cors-wildcard-with-credentials": "A05:2021",
            "frontend-target-blank-missing-noopener": "A05:2021",
        }

        for rule_id, category in expected.items():
            assert map_to_owasp(rule_id) == category


class TestSemgrepPipelineIntegration:
    def test_semgrep_pipeline_uses_frontend_rules(self, tmp_path, monkeypatch):
        """
        End-to-end check that SemgrepService.analyze_repository picks up
        frontend findings via the full pipeline (parser, OWASP mapper,
        statistics), not just the raw semgrep invocation.

        SEMGREP_CONFIG is monkeypatched to the local rule file (instead of
        "auto") purely to avoid a network call to the Semgrep registry in
        this test environment; CUSTOM_RULE_PATHS is cleared so the pack
        isn't scanned twice.
        """

        monkeypatch.setattr(runner_module, "SEMGREP_CONFIG", str(RULES_PATH))
        monkeypatch.setattr(runner_module, "CUSTOM_RULE_PATHS", [])

        target_dir = tmp_path / "repo"
        target_dir.mkdir()
        (target_dir / "Comment.jsx").write_text(
            "function Comment(props) {\n"
            "  return <div dangerouslySetInnerHTML={{__html: props.userComment}} />;\n"
            "}\n"
        )

        analysis = SemgrepService().analyze_repository(str(target_dir))

        rule_ids = [f.rule_id.rsplit(".", 1)[-1] for f in analysis.findings]
        assert "frontend-react-dangerously-set-innerhtml" in rule_ids
        assert "A03:2021" in analysis.owasp_categories
        assert analysis.total_findings >= 1


class TestVulnerableDemoFile:
    """
    Sanity check that the planted-vulnerability demo file used for live
    presentations (security/vulnerable_frontend_demo/XSSDemo.jsx) actually
    trips the rules it's meant to demonstrate.
    """

    def test_demo_file_trips_expected_rules(self):
        demo_file = BASE_DIR / "vulnerable_frontend_demo" / "XSSDemo.jsx"
        assert demo_file.exists()

        ids = _check_ids(_run_frontend_rules_only(demo_file))

        assert "frontend-react-dangerously-set-innerhtml" in ids
        assert "frontend-insecure-storage-of-token" in ids