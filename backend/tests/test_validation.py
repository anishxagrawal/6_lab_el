import pytest
from security.validation.filters import is_ignored_finding
from security.validation.confidence import calculate_confidence
from security.validation.deduplicator import deduplicate_findings
from security.validation.clustering import cluster_vulnerabilities
from security.validation.validator import run_validation_pipeline

def test_ignored_findings():
    # Ignored path (demo/test)
    assert is_ignored_finding("vulnerable_frontend_demo/src/index.js", "API_KEY = '123'")
    assert is_ignored_finding("tests/test_auth.py", "API_KEY = '123'")
    
    # Ignored files
    assert is_ignored_finding(".env.example", "API_KEY = '123'")
    assert is_ignored_finding("README.md", "Example: API_KEY = '123'")
    
    # Mock keywords
    assert is_ignored_finding("src/app.py", "API_KEY = 'your-secret-here'")
    
    # Valid finding
    assert not is_ignored_finding("src/config/production.py", "API_KEY = 'AKIAZXCVBNMASDFGHJKL'")


def test_confidence_scoring():
    repo_profile = {
        "languages": ["python"],
        "frameworks": ["fastapi"],
        "infrastructure": ["docker"],
    }
    
    # Legit pattern secret
    finding = {
        "file_path": "src/config.py",
        "snippet": "AWS_KEY = 'AKIA1234567890ABCDEF'",
        "source_type": "secrets",
        "provider": "AWS",
        "confidence": "HIGH"
    }
    score, status = calculate_confidence(finding, repo_profile)
    assert score >= 70
    assert status == "VALIDATED"
    
    # Mismatch language rule (React file in Python repo with no JS in profile)
    react_finding = {
        "file_path": "frontend/component.tsx",
        "snippet": "let api = 'sk-123'",
        "source_type": "secrets"
    }
    score, status = calculate_confidence(react_finding, repo_profile)
    assert score < 40
    assert status == "REJECTED"


def test_deduplication():
    findings = [
        {"secret_hash": "hash_1", "secret_type": "AWS Key", "file_path": "src/file_1.py", "line_number": 10, "snippet": "secret = 1"},
        {"secret_hash": "hash_1", "secret_type": "AWS Key", "file_path": "src/file_2.py", "line_number": 20, "snippet": "secret = 1"},
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert len(deduped[0]["occurrences"]) == 2


def test_clustering():
    findings = [
        {"secret_type": "AWS Key", "rule_id": "hardcoded_secret", "file_path": "src/f1.py", "occurrences": [{}]},
        {"secret_type": "OpenAI Key", "rule_id": "hardcoded_secret", "file_path": "src/f2.py", "occurrences": [{}]},
    ]
    clusters = cluster_vulnerabilities(findings)
    assert len(clusters) == 1
    assert clusters[0]["root_cause"] == "Hardcoded Secrets"
    assert clusters[0]["occurrences_count"] == 2
