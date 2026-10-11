# Authify

[![CI](https://github.com/akincenk/Authify/actions/workflows/ci.yml/badge.svg)](https://github.com/akincenk/Authify/actions/workflows/ci.yml)

A small FastAPI service for username/password registration and JWT access tokens, backed by SQLite.

## What it does

- `POST /register` creates a user. The password is hashed with bcrypt; plaintext is never stored or returned.
- `POST /token` exchanges username/password (OAuth2 password flow, form-encoded) for a signed HS256 access token that expires after `ACCESS_TOKEN_EXPIRE_MINUTES` (default 15).
- `GET /users/me` returns the current user for a valid `Authorization: Bearer <token>` header.

## Stack

Python 3.11+, FastAPI, PyJWT, bcrypt, SQLite (stdlib `sqlite3`). Everything lives in `main.py` (about 150 lines); tests are in `tests/`.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/docs. The app refuses to start without a `JWT_SECRET` of at least 32 characters.

### Docker

```bash
docker build -t authify .
docker run --rm -p 8000:8000 -e JWT_SECRET="$JWT_SECRET" -v authify-data:/data authify
```

The container runs as a non-root user and keeps the SQLite file in the `/data` volume.

## Configuration

See `.env.example`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `JWT_SECRET` | none (required) | HMAC signing key |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Token lifetime |
| `AUTHIFY_DB` | `authify.db` | SQLite file path |

## API

```bash
curl -X POST localhost:8000/register -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "correct-horse"}'
# 201 {"username": "alice", "created_at": "..."}

curl -X POST localhost:8000/token -d username=alice -d password=correct-horse
# 200 {"access_token": "<jwt>", "token_type": "bearer", "expires_in": 900}

curl localhost:8000/users/me -H "Authorization: Bearer <jwt>"
# 200 {"username": "alice", "created_at": "..."}
```

Errors: `409` duplicate username, `422` invalid input (username 3-50 chars of `A-Z a-z 0-9 _ . -`, password 8+ chars and at most 72 bytes), `401` bad credentials or an invalid/expired token. Wrong password and unknown user return the same response, and both run a bcrypt check so timing does not reveal which usernames exist.

## Tests

```bash
pip install -r requirements-dev.txt
ruff check . && pytest
```

The tests cover hashing, duplicates, validation, token expiry claims, and rejection of expired, expiry-less, wrongly signed, `alg=none` and unknown-user tokens. CI runs them on Python 3.11 and 3.12.

## Limitations / next steps

- Access tokens only: no refresh tokens, logout or revocation.
- No rate limiting or lockout on `/token`; put it behind a gateway that does this, or add it.
- SQLite with one connection per request suits a single instance, not a cluster.
- No email verification, password reset or roles.

## License

MIT, see [LICENSE](LICENSE).
