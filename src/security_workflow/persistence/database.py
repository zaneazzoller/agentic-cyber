from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from security_workflow.persistence.models import Base


def create_session_factory(database_url: str):
    return sessionmaker(bind=create_engine(database_url, pool_pre_ping=True), expire_on_commit=False)


def create_tables(database_url: str) -> None:
    """Development-only bootstrap. Production deployments must use reviewed migrations."""
    engine = create_engine(database_url, pool_pre_ping=True)
    Base.metadata.create_all(engine)
