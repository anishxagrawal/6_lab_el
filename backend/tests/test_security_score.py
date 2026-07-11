"""
Tests for the Phase 8 GET /repos/{repo_id}/score endpoint.

Uses a small fake Supabase client (not a real Supabase connection) so these
tests don't need live credentials - same spirit as tests/conftest.py's
placeholder env vars. The fake client only implements the
`.table(name).select(...).eq(...).execute()` chain the endpoint actually
uses.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import main
from main import app

client = TestClient(app)


class _FakeTable:
    def __init__(self, rows: list[dict]):
        self._rows = rows

    def select(self, *args, **kwargs):
        return self

    def eq(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def execute(self):
        return SimpleNamespace(data=self._rows)


class _FakeClient:
    """Serves canned rows for the 'repos' and 'findings' tables only."""

    def __init__(self, repo_rows: list[dict], finding_rows: list[dict]):
        self._repo_rows = repo_rows
        self._finding_rows = finding_rows

    def table(self, name: str):
        if name == "repos":
            return _FakeTable(self._repo_rows)
        if name == "findings":
            return _FakeTable(self._finding_rows)
        return _FakeTable([])


REPO_ID = "11111111-1111-1111-1111-111111111111"
FAKE_REPO_ROW = {"id": REPO_ID, "owner": "octocat", "name": "hello-world"}


def test_score_is_100_with_no_findings(monkeypatch):
    monkeypatch.setattr(main, "supabase", _FakeClient([FAKE_REPO_ROW], []))

    response = client.get(f"/repos/{REPO_ID}/score")

    assert response.status_code == 200
    body = response.json()
    assert body["security_score"] == 100
    assert body["breakdown"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_score_deducts_by_severity(monkeypatch):
    findings = (
        [{"severity": "CRITICAL"}] * 2
        + [{"severity": "HIGH"}] * 1
        + [{"severity": "MEDIUM"}] * 3
        + [{"severity": "LOW"}] * 1
    )
    monkeypatch.setattr(main, "supabase", _FakeClient([FAKE_REPO_ROW], findings))

    response = client.get(f"/repos/{REPO_ID}/score")

    assert response.status_code == 200
    body = response.json()
    # 100 - 2*15 - 1*8 - 3*4 - 1*2 = 100 - 30 - 8 - 12 - 2 = 48
    assert body["security_score"] == 48
    assert body["breakdown"] == {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3, "LOW": 1}


def test_score_floors_at_zero_with_many_criticals(monkeypatch):
    findings = [{"severity": "CRITICAL"}] * 20
    monkeypatch.setattr(main, "supabase", _FakeClient([FAKE_REPO_ROW], findings))

    response = client.get(f"/repos/{REPO_ID}/score")

    assert response.status_code == 200
    assert response.json()["security_score"] == 0


def test_score_ignores_unrecognized_severity_but_treats_missing_as_low(monkeypatch):
    # An unrecognized severity string isn't in the CRITICAL/HIGH/MEDIUM/LOW
    # bucket set, so it's silently ignored rather than crashing. A missing/
    # null severity is normalized to LOW (same fallback the rest of the
    # codebase uses for findings with no severity set).
    findings = [{"severity": "WEIRD"}, {"severity": None}]
    monkeypatch.setattr(main, "supabase", _FakeClient([FAKE_REPO_ROW], findings))

    response = client.get(f"/repos/{REPO_ID}/score")

    assert response.status_code == 200
    body = response.json()
    assert body["breakdown"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1}
    assert body["security_score"] == 98


def test_score_returns_404_for_unknown_repo(monkeypatch):
    monkeypatch.setattr(main, "supabase", _FakeClient([], []))

    response = client.get(f"/repos/{REPO_ID}/score")

    assert response.status_code == 404