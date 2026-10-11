import os
import tempfile

os.environ["JWT_SECRET"] = "test-secret-" + "x" * 32
os.environ["AUTHIFY_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402


@pytest.fixture
def client():
    if os.path.exists(main.DB_PATH):
        os.remove(main.DB_PATH)
    with TestClient(main.app) as c:  # runs lifespan -> creates the table
        yield c


@pytest.fixture
def register(client):
    def _register(username="alice", password="correct-horse"):
        return client.post("/register", json={"username": username, "password": password})

    return _register


@pytest.fixture
def token(client, register):
    register()
    return client.post("/token", data={"username": "alice", "password": "correct-horse"}).json()["access_token"]
