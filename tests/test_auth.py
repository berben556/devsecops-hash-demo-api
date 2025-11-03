import pytest
from fastapi.testclient import TestClient
from auth import router, oauth_states, generate_jwt_token, verify_jwt
from database import User
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials

app = FastAPI()
app.include_router(router)

client = TestClient(app)

# Dummy data
DUMMY_USER = User(id=1, gitlab_id=123, username="testuser", email="test@example.com")

JWT_ALGORITHM = "HS256"


def test_get_gitlab_oauth_url():
    response = client.get("/auth/gitlab/url")
    assert response.status_code == 200
    data = response.json()
    assert "auth_url" in data
    assert "state" in data
    assert data["state"] in oauth_states


def test_gitlab_callback_missing_fields():
    response = client.post("/auth/gitlab/callback", json={})
    assert response.status_code == 400


def test_gitlab_callback_invalid_state():
    response = client.post("/auth/gitlab/callback", json={"code": "x", "state": "fake"})
    assert response.status_code == 403


def test_gitlab_callback_token_error(monkeypatch):
    oauth_states.add("state")

    def fake_post(*args, **kwargs):
        class FakeResp:
            status_code = 400

        return FakeResp()

    monkeypatch.setattr("auth.requests.post", fake_post)

    response = client.post("/auth/gitlab/callback", json={"code": "x", "state": "state"})
    assert response.status_code == 400


def test_gitlab_callback_userinfo_error(monkeypatch):
    oauth_states.add("state")

    def fake_post(*args, **kwargs):
        class FakeResp:
            status_code = 200

            def json(self): return {"access_token": "abc"}

        return FakeResp()

    def fake_get(*args, **kwargs):
        class FakeResp:
            status_code = 400

        return FakeResp()

    monkeypatch.setattr("auth.requests.post", fake_post)
    monkeypatch.setattr("auth.requests.get", fake_get)

    response = client.post("/auth/gitlab/callback", json={"code": "x", "state": "state"})
    assert response.status_code == 400


def test_gitlab_callback_user_exists(monkeypatch):
    oauth_states.add("state")

    def fake_post(*args, **kwargs):
        class FakeResp:
            status_code = 200

            def json(self): return {"access_token": "abc"}

        return FakeResp()

    def fake_get(*args, **kwargs):
        class FakeResp:
            status_code = 200

            def json(self): return {"id": 123, "username": "testuser", "email": "test@example.com"}

        return FakeResp()

    monkeypatch.setattr("auth.requests.post", fake_post)
    monkeypatch.setattr("auth.requests.get", fake_get)
    monkeypatch.setattr("auth.get_user_by_gitlab_id", lambda x: DUMMY_USER)
    monkeypatch.setattr("auth.create_user", lambda *a, **kw: None)

    response = client.post("/auth/gitlab/callback", json={"code": "x", "state": "state"})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_generate_and_verify_jwt():
    token = generate_jwt_token(DUMMY_USER)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    verify_jwt(creds)


def test_verify_jwt_invalid():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="badtoken")
    with pytest.raises(HTTPException) as exc_info:
        verify_jwt(creds)
    assert exc_info.value.status_code == 403
