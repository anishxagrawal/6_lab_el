"""
Tests for POST /repos - registers a GitHub repo so it has a `repo_id` that
POST /scan can be called with.

Uses a small fake Supabase client (not a real Supabase connection), same
pattern as tests/test_security_score.py, so these don't need live
credentials.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import main
from main import app

client = TestClient(app)


class _FakeTable:
    """
    Serves canned `select` results and records `insert` calls for the
    'repos' table. Good enough for this endpoint's query shape:
    select(...).eq(...).limit(...).execute() and insert({...}).execute().
    """

    def __init__(self, existing_rows: list[dict], inserted_row: dict | None):
        self._existing_rows = existing_rows
        self._inserted_row = inserted_row
        self.insert_calls: list[dict] = []
        self._pending_insert = False

    def select(self, *args, **kwargs):
        self._pending_insert = False
        return self

    def eq(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def insert(self, payload: dict):
        self._pending_insert = True
        self.insert_calls.append(payload)
        return self

    def execute(self):
        if self._pending_insert:
            self._pending_insert = False
            return SimpleNamespace(data=[self._inserted_row] if self._inserted_row else [])
        return SimpleNamespace(data=self._existing_rows)


class _FakeClient:
    def __init__(self, repos_table: _FakeTable):
        self._repos_table = repos_table

    def table(self, name: str):
        if name == "repos":
            return self._repos_table
        return _FakeTable([], None)


def test_create_repo_rejects_malformed_url():
    response = client.post("/repos", json={"github_url": "not-a-url"})

    assert response.status_code == 400


def test_create_repo_rejects_url_with_injection_style_flag(monkeypatch):
    monkeypatch.setattr(main, "supabase", _FakeClient(_FakeTable([], None)))

    response = client.post(
        "/repos",
        json={"github_url": "https://github.com/--upload-pack=touch /tmp/pwned/x"},
    )

    assert response.status_code == 400


def test_create_repo_inserts_new_row(monkeypatch):
    inserted_row = {
        "id": "22222222-2222-2222-2222-222222222222",
        "owner": "octocat",
        "name": "hello-world",
        "github_url": "https://github.com/octocat/hello-world",
        "status": "pending",
        "finding_count": 0,
    }
    fake_table = _FakeTable(existing_rows=[], inserted_row=inserted_row)
    monkeypatch.setattr(main, "supabase", _FakeClient(fake_table))

    response = client.post(
        "/repos",
        json={"github_url": "https://github.com/octocat/hello-world"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["created"] is True
    assert body["owner"] == "octocat"
    assert body["name"] == "hello-world"
    assert body["status"] == "pending"
    assert fake_table.insert_calls == [
        {
            "owner": "octocat",
            "name": "hello-world",
            "github_url": "https://github.com/octocat/hello-world",
            "status": "pending",
            "finding_count": 0,
        }
    ]


def test_create_repo_is_idempotent_for_existing_url(monkeypatch):
    existing_row = {
        "id": "33333333-3333-3333-3333-333333333333",
        "owner": "octocat",
        "name": "hello-world",
        "github_url": "https://github.com/octocat/hello-world",
        "status": "done",
        "finding_count": 5,
    }
    fake_table = _FakeTable(existing_rows=[existing_row], inserted_row=None)
    monkeypatch.setattr(main, "supabase", _FakeClient(fake_table))

    response = client.post(
        "/repos",
        json={"github_url": "https://github.com/octocat/hello-world"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["created"] is False
    assert body["id"] == existing_row["id"]
    assert body["status"] == "done"
    # No insert should have been attempted once an existing row was found.
    assert fake_table.insert_calls == []


def test_create_repo_normalizes_dot_git_and_trailing_slash(monkeypatch):
    inserted_row = {
        "id": "44444444-4444-4444-4444-444444444444",
        "owner": "octocat",
        "name": "hello-world",
        "github_url": "https://github.com/octocat/hello-world",
        "status": "pending",
        "finding_count": 0,
    }
    fake_table = _FakeTable(existing_rows=[], inserted_row=inserted_row)
    monkeypatch.setattr(main, "supabase", _FakeClient(fake_table))

    response = client.post(
        "/repos",
        json={"github_url": "https://github.com/octocat/hello-world.git/"},
    )

    assert response.status_code == 200
    assert fake_table.insert_calls[0]["github_url"] == "https://github.com/octocat/hello-world"