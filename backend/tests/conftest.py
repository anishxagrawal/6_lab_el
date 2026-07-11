"""
Shared pytest fixtures and test-environment setup.

IMPORTANT: env vars used by main.py at import time (SUPABASE_URL, SUPABASE_KEY,
ENCRYPTION_KEY) are set here, at module load time, BEFORE any test module does
`from main import app`. This lets the whole app import cleanly in CI/local
test runs without needing real Supabase/GitHub/SMTP credentials.

None of these are real credentials - they're syntactically valid placeholders
so main.py's startup checks (e.g. `if not ENCRYPTION_KEY: raise RuntimeError`)
pass, and so the supabase-py client can be constructed without erroring out.
Any test that actually hits the network through this client would fail/hang,
so tests in this suite avoid exercising code paths that make real Supabase
or GitHub calls (those are integration-tested manually / in Phase 3+).
"""

import os

from cryptography.fernet import Fernet

os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "test-placeholder-key")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("HMAC_SECRET_KEY", "test-hmac-pepper")
os.environ.setdefault("GROQ_API_KEY", "")  # empty -> groq_client stays None in main.py
os.environ.setdefault("GITHUB_TOKEN", "")
os.environ.setdefault("SMTP_HOST", "")
os.environ.setdefault("SMTP_USER", "")
os.environ.setdefault("SMTP_PASSWORD", "")
os.environ.setdefault("ALERT_EMAIL_TO", "")

import pytest


@pytest.fixture
def fernet_key() -> str:
    """A fresh, valid Fernet key string for tests that build their own cipher."""
    return Fernet.generate_key().decode()


@pytest.fixture
def hmac_pepper() -> str:
    """A fixed pepper value for HMAC-based secret hashing tests."""
    return "unit-test-pepper-value"