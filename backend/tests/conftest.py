"""Pytest fixtures: an isolated temp-file SQLite DB + a fresh TestClient."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Use an isolated temp DB BEFORE app modules are imported
_TMPDIR = tempfile.mkdtemp(prefix="cybershield_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_TMPDIR) / 'test.db'}"
os.environ["ENVIRONMENT"] = "development"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-prod"
os.environ["ADMIN_EMAIL"] = "admin@cybershieldplatform.com"
os.environ["ADMIN_PASSWORD"] = "ChangeThis!Now12345"
os.environ["SCHEDULER_ENABLED"] = "false"

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def token(client):
    r = client.post("/api/v1/auth/login", data={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["token"]["access_token"]


@pytest.fixture
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}
