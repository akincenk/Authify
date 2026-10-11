"""Authify: a small JWT authentication service built with FastAPI.

Users are stored in SQLite with bcrypt-hashed passwords. Clients register,
exchange credentials for a short-lived access token (OAuth2 password flow),
and call protected endpoints with `Authorization: Bearer <token>`.
"""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator

SECRET_KEY = os.environ.get("JWT_SECRET", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET env var must be set to a random string of 32+ characters")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
DB_PATH = os.getenv("AUTHIFY_DB", "authify.db")

# Checked when the username does not exist, so a failed login takes about as
# long whether or not the user is registered (no username enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt()).decode()


def get_db() -> Iterator[sqlite3.Connection]:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        yield conn


def init_db() -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            " username TEXT PRIMARY KEY,"
            " hashed_password TEXT NOT NULL,"
            " created_at TEXT NOT NULL)"
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Authify", lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8)

    @field_validator("password")
    @classmethod
    def fits_bcrypt(cls, v: str) -> str:
        # bcrypt only uses the first 72 bytes; reject rather than silently truncate.
        if len(v.encode()) > 72:
            raise ValueError("password must be at most 72 bytes")
        return v


class User(BaseModel):
    username: str
    created_at: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:  # password over 72 bytes
        return False


def create_access_token(username: str) -> str:
    now = datetime.now(UTC)
    claims = {"sub": username, "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}
    return jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        raise unauthorized from None
    row = db.execute("SELECT username, created_at FROM users WHERE username = ?", (payload["sub"],)).fetchone()
    if row is None:
        raise unauthorized
    return User(username=row[0], created_at=row[1])


@app.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    created_at = datetime.now(UTC).isoformat()
    try:
        with db:
            db.execute(
                "INSERT INTO users (username, hashed_password, created_at) VALUES (?, ?, ?)",
                (body.username, hash_password(body.password), created_at),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already registered") from None
    return User(username=body.username, created_at=created_at)


@app.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    row = db.execute("SELECT hashed_password FROM users WHERE username = ?", (form.username,)).fetchone()
    valid = verify_password(form.password, row[0] if row else _DUMMY_HASH)
    if not (row and valid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(access_token=create_access_token(form.username), expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)


@app.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/health")
def health():
    return {"status": "ok"}
