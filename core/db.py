"""PostgreSQL access for app state (audit, conversations, credentials). Never stores secrets in plain text."""
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

from core.config import settings


class DatabaseError(Exception):
    """Raised with a safe message (no connection string or password)."""


def connect():
    try:
        return psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            dbname=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
            connect_timeout=5,
        )
    except psycopg2.OperationalError as e:
        first_line = str(e).strip().splitlines()[-1] if str(e).strip() else "unknown error"
        raise DatabaseError(f"Cannot connect to database '{settings.db_name}': {first_line}") from None


@contextmanager
def cursor(dict_rows: bool = False):
    """Yield a cursor inside a transaction; commit on success, rollback on error."""
    conn = connect()
    try:
        factory = psycopg2.extras.RealDictCursor if dict_rows else None
        with conn:
            with conn.cursor(cursor_factory=factory) as cur:
                yield cur
    finally:
        conn.close()


def fetch_all(sql: str, params=None) -> list[dict]:
    with cursor(dict_rows=True) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def fetch_one(sql: str, params=None):
    with cursor(dict_rows=True) as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None


def execute(sql: str, params=None):
    """Run a write; returns the first column of RETURNING if present."""
    with cursor() as cur:
        cur.execute(sql, params)
        if cur.description:
            row = cur.fetchone()
            return row[0] if row else None
    return None


def ping() -> tuple[bool, str]:
    try:
        fetch_one("SELECT 1 AS ok")
        return True, f"connected to {settings.db_name}"
    except Exception as e:
        return False, str(e)


def ensure_schema() -> list[str]:
    """Apply db/migrations/*.sql in order (each is idempotent: CREATE ... IF NOT EXISTS)."""
    from core.config import PROJECT_ROOT
    applied = []
    for path in sorted((PROJECT_ROOT / "db" / "migrations").glob("*.sql")):
        with cursor() as cur:
            cur.execute(path.read_text(encoding="utf-8"))
        applied.append(path.name)
    return applied


def new_conversation(title: str) -> int | None:
    try:
        return execute("INSERT INTO conversations (title) VALUES (%s) RETURNING id", (title[:200],))
    except Exception:
        return None


def save_message(conversation_id: int | None, role: str, content: str) -> None:
    if conversation_id is None:
        return
    try:
        execute(
            "INSERT INTO messages (conversation_id, role, content) VALUES (%s, %s, %s)",
            (conversation_id, role, content),
        )
    except Exception:
        pass
