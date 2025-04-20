# Authify

Authify is a production-ready authentication microservice built using FastAPI. It implements user registration, login via OAuth2PasswordRequestForm, JWT access tokens, and protected user routes.

## Features

- Register new users (`/register`)
- Login with username & password (`/token`)
- Secure JWT-based authentication
- Access protected routes (`/users/me`)

## Stack

- FastAPI
- Python-Jose (JWT)
- Passlib (bcrypt)
- Uvicorn

## How to Run

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Or use Docker:

```bash
docker build -t authify .
docker run -p 8000:8000 authify
```

## Example Usage

1. **Register a user**

```
POST /register
FormData:
  username: myuser
  password: mypass
```

2. **Login and get token**

```
POST /token
FormData:
  username: myuser
  password: mypass
```

3. **Access protected route**

```
GET /users/me
Header:
  Authorization: Bearer <your_token>
```

---

© 2025
