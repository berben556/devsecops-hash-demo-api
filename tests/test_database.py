import pytest
from sqlmodel import SQLModel, Session, create_engine, select
import database
from database import User, create_user, get_user_by_gitlab_id, log_hash_request, HashRecord

test_engine = create_engine("sqlite://", echo=False)


@pytest.fixture
def create_test_db():
    SQLModel.metadata.create_all(test_engine)
    yield
    SQLModel.metadata.drop_all(test_engine)


@pytest.fixture
def session(create_test_db):
    with Session(test_engine) as session:
        yield session


@pytest.fixture(autouse=True)
def override_get_engine(monkeypatch):
    monkeypatch.setattr(database, "get_engine", lambda: test_engine)


def test_create_user(session):
    user = create_user(gitlab_id=12345, username="testuser", email="test@example.com")

    assert user.id is not None
    assert user.gitlab_id == 12345
    assert user.username == "testuser"
    assert user.email == "test@example.com"


def test_get_user_by_gitlab_id(session):
    with Session(test_engine) as s:
        s.add(User(gitlab_id=9999, username="testuser", email="test@example.com"))
        s.commit()

    fetched = get_user_by_gitlab_id(9999)
    assert fetched is not None
    assert fetched.username == "testuser"


def test_get_user_by_gitlab_id_not_found(session):
    not_found = get_user_by_gitlab_id(123456)
    assert not_found is None


def test_log_hash_request_new_entry(session):
    log_hash_request("sha256", "hello", "abc123")

    with Session(test_engine) as s:
        result = s.exec(
            select(HashRecord).where(HashRecord.algorithm == "sha256", HashRecord.input_text == "hello")
        ).first()

        assert result is not None
        assert result.hashed_value == "abc123"


def test_log_hash_request_duplicate_entry(session):
    log_hash_request("md5", "duplicate", "hash123")
    log_hash_request("md5", "duplicate", "hash123")  # duplicate should not raise

    with Session(test_engine) as s:
        results = s.exec(
            select(HashRecord).where(HashRecord.algorithm == "md5", HashRecord.input_text == "duplicate")
        ).all()
        assert len(results) == 1
