"""
Basic API smoke test. Relies on tests/conftest.py having already set
placeholder env vars before `main` is imported, so the app can be
constructed without real Supabase/GitHub/SMTP credentials.
"""

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_endpoint_returns_ok():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_schema_is_available():
    # Confirms the app + all routes construct without errors and /docs
    # (Swagger) has something valid to render.
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert "/health" in schema["paths"]
    assert "/scan" in schema["paths"]