import pytest
import os
import json
import tempfile
from security.codeql.parser import map_sarif_severity, extract_cwe_from_tags, parse_codeql_sarif
from security.correlation.correlator import correlate_scanner_findings
from security.validation.confidence import calculate_confidence

def test_map_sarif_severity():
    # Security severity score maps
    assert map_sarif_severity({}, {"properties": {"security-severity": "9.5"}}) == "CRITICAL"
    assert map_sarif_severity({}, {"properties": {"security-severity": "8.0"}}) == "HIGH"
    assert map_sarif_severity({}, {"properties": {"security-severity": "5.5"}}) == "MEDIUM"
    assert map_sarif_severity({}, {"properties": {"security-severity": "2.0"}}) == "LOW"

    # Level maps
    assert map_sarif_severity({"level": "error"}, {}) == "CRITICAL"
    assert map_sarif_severity({"level": "warning"}, {}) == "HIGH"
    assert map_sarif_severity({"level": "note"}, {}) == "MEDIUM"
    assert map_sarif_severity({}, {}) == "HIGH"  # Default level fallback


def test_extract_cwe_from_tags():
    assert extract_cwe_from_tags({"tags": ["external/cwe/cwe-89"]}) == "CWE-89"
    assert extract_cwe_from_tags({"tags": ["random", "cwe-79"]}) == "CWE-79"
    assert extract_cwe_from_tags({"tags": []}) == "CWE-200"


def test_parse_codeql_sarif():
    sarif_data = {
        "runs": [{
            "tool": {
                "driver": {
                    "rules": [{
                        "id": "py/sql-injection",
                        "shortDescription": {"text": "SQL Injection"},
                        "properties": {
                            "security-severity": "9.2",
                            "tags": ["external/cwe/cwe-89"],
                            "precision": "high"
                        }
                    }]
                }
            },
            "results": [{
                "ruleId": "py/sql-injection",
                "message": {"text": "SQL injection detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 10}
                    }
                }],
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 5}
                                    },
                                    "message": {"text": "source input"}
                                }
                            },
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 10}
                                    },
                                    "message": {"text": "sink run"}
                                }
                            }
                        ]
                    }]
                }]
            }]
        }]
    }

    with tempfile.NamedTemporaryFile(suffix=".sarif", mode="w", delete=False, encoding="utf-8") as tmp:
        json.dump(sarif_data, tmp)
        tmp_name = tmp.name

    try:
        findings = parse_codeql_sarif(tmp_name)
        assert len(findings) == 1
        f = findings[0]
        assert f.file_path == "src/app.py"
        assert f.line_number == 10
        assert f.rule_id == "py/sql-injection"
        assert f.severity == "CRITICAL"
        assert f.cwe == "CWE-89"
        assert len(f.code_flow) == 2
        assert f.code_flow[0]["label"] == "Source: source input"
        assert f.code_flow[1]["label"] == "Sink: sink run"
    finally:
        os.remove(tmp_name)


def test_correlate_scanner_findings():
    raw_findings = [
        {
            "source_type": "semgrep",
            "file_path": "src/app.py",
            "line_number": 10,
            "snippet": "db.execute(sql)",
            "rule_id": "sql_injection",
            "cwe": "CWE-89",
            "severity": "CRITICAL"
        },
        {
            "source_type": "codeql",
            "file_path": "src/app.py",
            "line_number": 10,
            "snippet": "db.execute(sql)",
            "rule_id": "py/sql-injection",
            "cwe": "CWE-89",
            "severity": "CRITICAL",
            "code_flow": [{"file": "src/app.py", "line": 5, "label": "Source"}]
        }
    ]

    correlated = correlate_scanner_findings(raw_findings, {})
    assert len(correlated) == 1
    c = correlated[0]
    assert "semgrep" in c["supporting_scanners"]
    assert "codeql" in c["supporting_scanners"]
    assert len(c["code_flow"]) == 1
    assert c["confidence_modifier"] == 25  # Scanner agreement boost


def test_correlate_disagreement_heuristic():
    # If CodeQL ran but did not find anything, decrease confidence for Semgrep finding
    raw_findings = [
        {
            "source_type": "semgrep",
            "file_path": "src/app.py",
            "line_number": 10,
            "snippet": "db.execute(sql)",
            "rule_id": "sql_injection",
            "cwe": "CWE-89",
            "severity": "CRITICAL"
        },
        {
            "source_type": "codeql",
            "file_path": "src/other.py",
            "line_number": 20,
            "snippet": "other query",
            "rule_id": "py/sql-injection",
            "cwe": "CWE-89",
            "severity": "HIGH"
        }
    ]

    correlated = correlate_scanner_findings(raw_findings, {})
    # Should yield two findings since they are in different files
    assert len(correlated) == 2
    
    semgrep_finding = next(f for f in correlated if f["source_type"] == "semgrep")
    assert semgrep_finding["confidence_modifier"] == -35  # CodeQL disagreement reduction
