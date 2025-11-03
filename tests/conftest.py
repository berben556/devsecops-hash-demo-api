import os
import pytest


@pytest.fixture(scope="session", autouse=True)
def set_test_env_vars():
    os.environ["GITLAB_CLIENT_ID"] = "dummy_id"
    os.environ["GITLAB_CLIENT_SECRET"] = "dummy_secret"
    os.environ["GITLAB_REDIRECT_URI"] = "http://localhost/callback"
    os.environ["GITLAB_TOKEN_URL"] = "http://mock/token"
    os.environ["GITLAB_USER_API_URL"] = "http://mock/user"
    os.environ["DATABASE_URL"] = "sqlite://"
    os.environ["JWT_SECRET"] = "dummy_jwt"
