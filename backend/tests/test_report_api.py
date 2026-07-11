"""
Endpoint-level tests for the Phase 7 signed-report routes:
GET /reports/public-key and POST /reports/verify.

Relies on tests/conftest.py having already set placeholder env vars before
`main` is imported, so the app (and its report-signing keypair) can be
constructed without real Supabase/GitHub/SMTP credentials.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from main import app, SIGNING_PRIVATE_KEY
from security.report_signing import sign_report

client = TestClient(app)


def test_public_key_endpoint_returns_well_formed_pem():
    response = client.get("/reports/public-key")

    assert response.status_code == 200
    pem = response.json()["public_key_pem"]
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert "-----END PUBLIC KEY-----" in pem


def test_verify_endpoint_accepts_a_valid_signature():
    report = {
        "repo_id": "test-repo-id",
        "owner": "octocat",
        "name": "hello-world",
        "total_findings": 3,
        "critical_findings": 1,
    }
    signature = sign_report(report, SIGNING_PRIVATE_KEY)

    response = client.post(
        "/reports/verify",
        json={"report": report, "signature": signature},
    )

    assert response.status_code == 200
    assert response.json() == {"valid": True}


def test_verify_endpoint_rejects_a_tampered_report():
    report = {
        "repo_id": "test-repo-id",
        "owner": "octocat",
        "name": "hello-world",
        "total_findings": 3,
        "critical_findings": 1,
    }
    signature = sign_report(report, SIGNING_PRIVATE_KEY)

    tampered_report = dict(report)
    tampered_report["critical_findings"] = 99

    response = client.post(
        "/reports/verify",
        json={"report": tampered_report, "signature": signature},
    )

    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_verify_endpoint_rejects_garbage_signature():
    report = {"repo_id": "x", "owner": "a", "name": "b"}

    response = client.post(
        "/reports/verify",
        json={"report": report, "signature": "0000"},
    )

    assert response.status_code == 200
    assert response.json() == {"valid": False}