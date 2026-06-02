import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

DB_PATH = os.getenv("DB_PATH", "/data/threatfeed.db")

# Single write lock prevents read-modify-write races on occurrences_count.
# WAL journal mode handles file-level concurrent reads without this lock.
_write_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _read_db():
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _write_db():
    with _write_lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_db() -> None:
    with _write_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threat_feed (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                element     TEXT    NOT NULL UNIQUE,
                data_type   TEXT    NOT NULL,
                entry_type  TEXT    NOT NULL,
                expires_at  TEXT,
                created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE TABLE IF NOT EXISTS threat_history (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                element           TEXT    NOT NULL UNIQUE,
                data_type         TEXT    NOT NULL,
                occurrences_count INTEGER NOT NULL DEFAULT 1,
                last_seen         TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_feed_dtype_etype
                ON threat_feed(data_type, entry_type);

            CREATE INDEX IF NOT EXISTS idx_history_count
                ON threat_history(occurrences_count DESC);
        """)


def process_feed_entry(
    element: str,
    data_type: str,
    entry_type: str,
    expires_at: Optional[str],
    threshold: int,
    promotion_enabled: bool = True,
) -> dict:
    """
    Single atomic transaction:
      1. Upsert threat_feed (permanent never downgrades to temporary).
      2. Increment threat_history counter.
      3. Promote to permanent in threat_feed if count >= threshold.

    Returns {"occurrences_count": int, "promoted": bool}
    """
    with _write_db() as conn:
        # ── 1. Upsert threat_feed ─────────────────────────────────────────────
        existing = conn.execute(
            "SELECT entry_type FROM threat_feed WHERE element = ?", (element,)
        ).fetchone()

        if existing is None:
            conn.execute(
                "INSERT INTO threat_feed (element, data_type, entry_type, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (element, data_type, entry_type, expires_at),
            )
        elif existing["entry_type"] != "permanent":
            # Temporary → update expiry / type (could be immediate upgrade to permanent)
            conn.execute(
                "UPDATE threat_feed SET data_type=?, entry_type=?, expires_at=? "
                "WHERE element=?",
                (data_type, entry_type, expires_at, element),
            )
        # existing permanent → leave untouched (no downgrade)

        # ── 2. Upsert threat_history ──────────────────────────────────────────
        now = _now_utc()
        hist = conn.execute(
            "SELECT occurrences_count FROM threat_history WHERE element = ?", (element,)
        ).fetchone()

        if hist is None:
            conn.execute(
                "INSERT INTO threat_history (element, data_type, occurrences_count, last_seen) "
                "VALUES (?, ?, 1, ?)",
                (element, data_type, now),
            )
            count = 1
        else:
            count = hist["occurrences_count"] + 1
            conn.execute(
                "UPDATE threat_history SET occurrences_count=?, last_seen=? WHERE element=?",
                (count, now, element),
            )

        # ── 3. Auto-promote if threshold reached ──────────────────────────────
        promoted = False
        if promotion_enabled and count >= threshold:
            cursor = conn.execute(
                "UPDATE threat_feed SET entry_type='permanent', expires_at=NULL "
                "WHERE element=? AND entry_type='temporary'",
                (element,),
            )
            promoted = cursor.rowcount > 0

        return {"occurrences_count": count, "promoted": promoted}


def delete_feed(element: str) -> bool:
    with _write_db() as conn:
        cursor = conn.execute("DELETE FROM threat_feed WHERE element = ?", (element,))
        return cursor.rowcount > 0


def get_permanent_feed(data_types: list[str]) -> list[str]:
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT element FROM threat_feed "
            f"WHERE data_type IN ({ph}) AND entry_type='permanent' "
            f"ORDER BY element",
            data_types,
        ).fetchall()
    return [r["element"] for r in rows]


def get_temporary_feed(data_types: list[str]) -> list[str]:
    now = _now_utc()
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT element FROM threat_feed "
            f"WHERE data_type IN ({ph}) AND entry_type='temporary' AND expires_at > ? "
            f"ORDER BY element",
            (*data_types, now),
        ).fetchall()
    return [r["element"] for r in rows]


def get_active_feed(data_types: list[str]) -> list[str]:
    """Permanent + non-expired temporary — the canonical FortiGate block list."""
    now = _now_utc()
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT element FROM threat_feed "
            f"WHERE data_type IN ({ph}) "
            f"AND (entry_type='permanent' OR (entry_type='temporary' AND expires_at > ?)) "
            f"ORDER BY element",
            (*data_types, now),
        ).fetchall()
    return [r["element"] for r in rows]


def get_stats() -> dict:
    now = _now_utc()
    with _read_db() as conn:
        feed: dict[str, dict] = {}
        for dtype in ("ip", "cidr", "domain"):
            perm = conn.execute(
                "SELECT COUNT(*) FROM threat_feed WHERE data_type=? AND entry_type='permanent'",
                (dtype,),
            ).fetchone()[0]
            tmp_active = conn.execute(
                "SELECT COUNT(*) FROM threat_feed "
                "WHERE data_type=? AND entry_type='temporary' AND expires_at > ?",
                (dtype, now),
            ).fetchone()[0]
            tmp_expired = conn.execute(
                "SELECT COUNT(*) FROM threat_feed "
                "WHERE data_type=? AND entry_type='temporary' AND expires_at <= ?",
                (dtype, now),
            ).fetchone()[0]
            feed[dtype] = {
                "permanent": perm,
                "temporary_active": tmp_active,
                "temporary_expired": tmp_expired,
            }

        total_elements = conn.execute(
            "SELECT COUNT(*) FROM threat_history"
        ).fetchone()[0]
        total_occurrences = conn.execute(
            "SELECT COALESCE(SUM(occurrences_count), 0) FROM threat_history"
        ).fetchone()[0]

    return {
        "feed": feed,
        "history": {
            "total_unique_elements": total_elements,
            "total_occurrences": total_occurrences,
        },
    }


def get_history() -> list[dict]:
    with _read_db() as conn:
        rows = conn.execute(
            "SELECT element, data_type, occurrences_count, last_seen "
            "FROM threat_history "
            "ORDER BY occurrences_count DESC, last_seen DESC"
        ).fetchall()
    return [dict(r) for r in rows]
