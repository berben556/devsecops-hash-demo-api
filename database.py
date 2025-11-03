import os
from starlette.config import Config
from sqlalchemy import UniqueConstraint
from sqlalchemy.exc import IntegrityError
from sqlmodel import SQLModel, Field, Session, create_engine, select
from typing import Optional


# --- Models ---
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    gitlab_id: int = Field(index=True, unique=True)
    username: str
    email: str


class HashRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    algorithm: str
    input_text: str
    hashed_value: str

    __table_args__ = (  # contrainte d'unicité du hash
        UniqueConstraint("algorithm", "input_text"),
    )


# --- DB setup ---
config = Config(".env") if os.path.exists(".env") else Config()
DATABASE_URL = config("DATABASE_URL")
_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL)
    return _engine


def init_db():
    SQLModel.metadata.create_all(get_engine())


# --- DB Operations ---
def create_user(gitlab_id: int, username: str, email: str) -> User:
    with Session(get_engine()) as session:
        user = User(gitlab_id=gitlab_id, username=username, email=email)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def get_user_by_gitlab_id(gitlab_id: int) -> User | None:
    with Session(get_engine()) as session:
        statement = select(User).where(User.gitlab_id == gitlab_id)
        user = session.exec(statement).first()
        return user


def log_hash_request(algorithm: str, input_text: str, hashed_value: str) -> None:
    """
    Sauvegarde la hash dans la rainbow table.
    Si le hash existe déjà une erreur est levée et puis traitée.
    """
    with Session(get_engine()) as session:
        try:
            record = HashRecord(
                algorithm=algorithm,
                input_text=input_text,
                hashed_value=hashed_value
            )
            session.add(record)
            session.commit()
        except IntegrityError:
            session.rollback()
