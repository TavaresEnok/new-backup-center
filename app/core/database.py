import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from app.core.config import settings


def _pool_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = str(os.getenv(name, default)).strip()
    try:
        value = int(raw)
    except Exception:
        value = int(default)
    return max(minimum, value)


# Pool dimensionado para suportar o pico do backup em massa, onde cada worker
# prefork abre varias sessoes sequenciais por task. Sem pool_size/max_overflow
# explicitos o SQLAlchemy usa 5+10; sob carga o pool_timeout estourava e gerava
# erros classificados como "timeout". Configuravel por env.
DB_POOL_SIZE = _pool_int("DB_POOL_SIZE", 10)
DB_MAX_OVERFLOW = _pool_int("DB_MAX_OVERFLOW", 20, minimum=0)
DB_POOL_TIMEOUT = _pool_int("DB_POOL_TIMEOUT", 30)

# engine = create_engine(settings.DATABASE_URL)
# For development/quick start with local postgres, ensure the URL is correct
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    pool_timeout=DB_POOL_TIMEOUT,
    pool_use_lifo=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)

Base = declarative_base()


def is_sqlite_engine() -> bool:
    """True quando DATABASE_URL é SQLite (ex.: testes/CI). Patches SQL específicos de PostgreSQL devem ser ignorados."""
    return engine.dialect.name == "sqlite"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
