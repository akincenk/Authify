import sqlite3
from datetime import UTC, datetime, timedelta

import jwt

import main


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_register_returns_user_without_password(register):
    r = register()
    assert r.status_code == 201
    assert r.json()["username"] == "alice"
    assert "password" not in r.text and "hashed" not in r.text


def test_password_stored_as_bcrypt_hash(register):
    register()
    with sqlite3.connect(main.DB_PATH) as conn:
        (stored,) = conn.execute("SELECT hashed_password FROM users WHERE username='alice'").fetchone()
    assert stored != "correct-horse"
    assert stored.startswith("$2b$")


def test_duplicate_username_conflict(register):
    assert register().status_code == 201
    assert register().status_code == 409


def test_register_validation(register):
    assert register(username="ab").status_code == 422
    assert register(username="bad name!").status_code == 422
    assert register(password="short").status_code == 422
    assert register(password="x" * 73).status_code == 422


def test_login_returns_expiring_token(client, register):
    register()
    r = client.post("/token", data={"username": "alice", "password": "correct-horse"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == main.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    claims = jwt.decode(body["access_token"], main.SECRET_KEY, algorithms=[main.ALGORITHM])
    assert claims["sub"] == "alice"
    assert 0 < claims["exp"] - claims["iat"] <= main.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def test_login_failures_are_indistinguishable(client, register):
    register()
    wrong_pw = client.post("/token", data={"username": "alice", "password": "wrong-password"})
    no_user = client.post("/token", data={"username": "nobody", "password": "wrong-password"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


def test_me_with_valid_token(client, token):
    r = client.get("/users/me", headers=bearer(token))
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_me_rejects_missing_or_garbage_token(client):
    assert client.get("/users/me").status_code == 401
    assert client.get("/users/me", headers=bearer("not-a-jwt")).status_code == 401


def test_me_rejects_expired_token(client, token):
    past = datetime.now(UTC) - timedelta(minutes=5)
    expired = jwt.encode({"sub": "alice", "iat": past, "exp": past}, main.SECRET_KEY, algorithm="HS256")
    assert client.get("/users/me", headers=bearer(expired)).status_code == 401


def test_me_rejects_token_without_expiry(client, token):
    forever = jwt.encode({"sub": "alice"}, main.SECRET_KEY, algorithm="HS256")
    assert client.get("/users/me", headers=bearer(forever)).status_code == 401


def test_me_rejects_wrong_signature_and_alg_none(client, token):
    exp = datetime.now(UTC) + timedelta(minutes=5)
    forged = jwt.encode({"sub": "alice", "exp": exp}, "other-secret-" + "y" * 32, algorithm="HS256")
    unsigned = jwt.encode({"sub": "alice", "exp": exp}, None, algorithm="none")
    assert client.get("/users/me", headers=bearer(forged)).status_code == 401
    assert client.get("/users/me", headers=bearer(unsigned)).status_code == 401


def test_me_rejects_token_for_unknown_user(client, token):
    ghost = main.create_access_token("ghost")
    assert client.get("/users/me", headers=bearer(ghost)).status_code == 401


def test_usernames_are_case_insensitive(client, register):
    r = register(username="Alice")
    assert r.status_code == 201
    assert r.json()["username"] == "alice"
    assert register(username="ALICE").status_code == 409
    r = client.post("/token", data={"username": "aLiCe", "password": "correct-horse"})
    assert r.status_code == 200
    assert client.get("/users/me", headers=bearer(r.json()["access_token"])).json()["username"] == "alice"


def test_token_endpoint_is_rate_limited(client, register):
    register()
    creds = {"username": "alice", "password": "wrong-password"}
    for _ in range(main.LOGIN_ATTEMPTS_PER_MINUTE):
        assert client.post("/token", data=creds).status_code == 401
    r = client.post("/token", data=creds)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0
    # even correct credentials are refused until the window passes
    assert client.post("/token", data={"username": "alice", "password": "correct-horse"}).status_code == 429


def test_rate_limit_window_slides(client, register, monkeypatch):
    register()
    now = [1000.0]
    monkeypatch.setattr(main.time, "monotonic", lambda: now[0])
    creds = {"username": "alice", "password": "wrong-password"}
    for _ in range(main.LOGIN_ATTEMPTS_PER_MINUTE):
        client.post("/token", data=creds)
    assert client.post("/token", data=creds).status_code == 429
    now[0] += 61
    assert client.post("/token", data={"username": "alice", "password": "correct-horse"}).status_code == 200


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
