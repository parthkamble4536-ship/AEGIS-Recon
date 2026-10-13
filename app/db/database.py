"""
Database connection management for AEGIS-Recon.

Provides a thread-safe SQLite connection pool with:
- Automatic schema initialization on first connect.
- WAL mode for concurrent reads during long scans.
- Foreign key enforcement enabled.
- Context manager for transaction safety.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from app.core.errors import DatabaseError
from app.core.logging import get_logger
from app.db.models import SCHEMA_SQL

logger = get_logger(__name__)

# Thread-local storage for connections
_local = threading.local()
_db_path: str | None = None
_initialized = False


def init_db(db_path: str) -> None:
    """
    Initialize the database: create the file, tables, and indexes.

    Args:
        db_path: Path to the SQLite database file.

    Raises:
        DatabaseError: If initialization fails.
    """
    global _db_path, _initialized

    try:
        path = Path(db_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        conn.close()

        _db_path = str(path)
        _initialized = True

        logger.info("database_initialized", path=str(path))

    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to initialize database: {e}") from e


def get_connection() -> sqlite3.Connection:
    """
    Get a thread-local database connection.

    Returns:
        sqlite3.Connection configured for AEGIS-Recon.

    Raises:
        DatabaseError: If the database is not initialized or connection fails.
    """
    if not _initialized or _db_path is None:
        raise DatabaseError(
            "Database not initialized. Call init_db() first.",
        )

    # Return existing thread-local connection if available
    conn = getattr(_local, "connection", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return conn
        except sqlite3.Error:
            # Connection is broken, create a new one
            pass

    try:
        conn = sqlite3.connect(_db_path)
        conn.row_factory = sqlite3.Row  # Dict-like access to columns
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.connection = conn
        return conn
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to connect to database: {e}") from e


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for database transactions.

    Automatically commits on success and rolls back on error.

    Yields:
        sqlite3.Connection with active transaction.

    Raises:
        DatabaseError: If the operation fails.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise DatabaseError(f"Database operation failed: {e}") from e
    except Exception:
        conn.rollback()
        raise


def close_db() -> None:
    """Close the thread-local database connection."""
    conn = getattr(_local, "connection", None)
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error:
            pass
        _local.connection = None


def reset_db() -> None:
    """Reset database state (for testing only)."""
    global _db_path, _initialized
    close_db()
    _db_path = None
    _initialized = False
