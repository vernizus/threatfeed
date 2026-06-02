import ipaddress
import os
import re
import sqlite3
import threading
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = os.getenv("DB_PATH", "/data/threatfeed.db")

_write_lock = threading.Lock()

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


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


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    with _write_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threat_feed (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                element     TEXT    NOT NULL UNIQUE,
                data_type   TEXT    NOT NULL,
                entry_type  TEXT    NOT NULL,
                expires_at  TEXT,
                source      TEXT    NOT NULL DEFAULT 'manual',
                comment     TEXT,
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
        # Migrate existing DBs that predate source/comment columns
        for col, definition in (
            ("source",  "TEXT NOT NULL DEFAULT 'manual'"),
            ("comment", "TEXT"),
        ):
            try:
                conn.execute(f"ALTER TABLE threat_feed ADD COLUMN {col} {definition}")
            except sqlite3.OperationalError:
                pass  # column already exists


# ── Core write operation ──────────────────────────────────────────────────────

def process_feed_entry(
    element: str,
    data_type: str,
    entry_type: str,
    expires_at: Optional[str],
    threshold: int,
    promotion_enabled: bool,
    source: str,
    comment: Optional[str],
) -> dict:
    """
    Atomic: upsert feed → increment history → promote if threshold.
    Permanent entries: entry_type/expires_at never downgrade, but source/comment always update.
    Returns {"occurrences_count": int, "promoted": bool}
    """
    with _write_db() as conn:
        existing = conn.execute(
            "SELECT entry_type FROM threat_feed WHERE element = ?", (element,)
        ).fetchone()

        if existing is None:
            conn.execute(
                "INSERT INTO threat_feed "
                "(element, data_type, entry_type, expires_at, source, comment) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (element, data_type, entry_type, expires_at, source, comment),
            )
        elif existing["entry_type"] == "permanent":
            # Keep permanent — only update metadata
            conn.execute(
                "UPDATE threat_feed SET source=?, comment=? WHERE element=?",
                (source, comment, element),
            )
        else:
            conn.execute(
                "UPDATE threat_feed "
                "SET data_type=?, entry_type=?, expires_at=?, source=?, comment=? "
                "WHERE element=?",
                (data_type, entry_type, expires_at, source, comment, element),
            )

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

        promoted = False
        if promotion_enabled and count >= threshold:
            cursor = conn.execute(
                "UPDATE threat_feed SET entry_type='permanent', expires_at=NULL "
                "WHERE element=? AND entry_type='temporary'",
                (element,),
            )
            promoted = cursor.rowcount > 0

        return {"occurrences_count": count, "promoted": promoted}


# ── Delete ────────────────────────────────────────────────────────────────────

def delete_feed(element: str) -> bool:
    with _write_db() as conn:
        cursor = conn.execute("DELETE FROM threat_feed WHERE element = ?", (element,))
        return cursor.rowcount > 0


# ── Plain-text feed queries (firewall consumable) ────────────────────────────

def _active_where(ph: str) -> str:
    return (
        f"WHERE data_type IN ({ph}) "
        f"AND (entry_type='permanent' OR (entry_type='temporary' AND expires_at > ?))"
    )


def get_permanent_feed(data_types: list[str]) -> list[str]:
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT element FROM threat_feed WHERE data_type IN ({ph}) "
            f"AND entry_type='permanent' ORDER BY element",
            data_types,
        ).fetchall()
    return [r["element"] for r in rows]


def get_temporary_feed(data_types: list[str]) -> list[str]:
    now = _now_utc()
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT element FROM threat_feed WHERE data_type IN ({ph}) "
            f"AND entry_type='temporary' AND expires_at > ? ORDER BY element",
            (*data_types, now),
        ).fetchall()
    return [r["element"] for r in rows]


def get_active_feed(data_types: list[str]) -> list[str]:
    now = _now_utc()
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT element FROM threat_feed {_active_where(ph)} ORDER BY element",
            (*data_types, now),
        ).fetchall()
    return [r["element"] for r in rows]


# ── Detail feed queries (SOC tools) ──────────────────────────────────────────

def _detail_cols() -> str:
    return "element, data_type, entry_type, source, comment, expires_at"


def get_permanent_feed_detail(data_types: list[str]) -> list[dict]:
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT {_detail_cols()} FROM threat_feed "
            f"WHERE data_type IN ({ph}) AND entry_type='permanent' ORDER BY element",
            data_types,
        ).fetchall()
    return [dict(r) for r in rows]


def get_temporary_feed_detail(data_types: list[str]) -> list[dict]:
    now = _now_utc()
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT {_detail_cols()} FROM threat_feed "
            f"WHERE data_type IN ({ph}) AND entry_type='temporary' AND expires_at > ? "
            f"ORDER BY element",
            (*data_types, now),
        ).fetchall()
    return [dict(r) for r in rows]


def get_active_feed_detail(data_types: list[str]) -> list[dict]:
    now = _now_utc()
    ph = ",".join("?" * len(data_types))
    with _read_db() as conn:
        rows = conn.execute(
            f"SELECT {_detail_cols()} FROM threat_feed {_active_where(ph)} ORDER BY element",
            (*data_types, now),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Lookup ────────────────────────────────────────────────────────────────────

def is_blocked(element: str) -> bool:
    """Lightweight check — no auth needed. True if element is currently active in feed."""
    now = _now_utc()
    with _read_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM threat_feed WHERE element = ? "
            "AND (entry_type='permanent' OR (entry_type='temporary' AND expires_at > ?)) LIMIT 1",
            (element, now),
        ).fetchone()
    return row is not None


def lookup_element(element: str) -> dict:
    now = _now_utc()
    with _read_db() as conn:
        feed_row = conn.execute(
            "SELECT element, data_type, entry_type, source, comment, expires_at, created_at "
            "FROM threat_feed WHERE element = ?",
            (element,),
        ).fetchone()
        hist_row = conn.execute(
            "SELECT occurrences_count, last_seen FROM threat_history WHERE element = ?",
            (element,),
        ).fetchone()

    if feed_row is None:
        return {"element": element, "found": False, "feed": None, "history": None}

    active = (
        feed_row["entry_type"] == "permanent"
        or (feed_row["expires_at"] is not None and feed_row["expires_at"] > now)
    )

    return {
        "element": element,
        "found": True,
        "feed": {
            "data_type": feed_row["data_type"],
            "entry_type": feed_row["entry_type"],
            "source": feed_row["source"],
            "comment": feed_row["comment"],
            "expires_at": feed_row["expires_at"],
            "created_at": feed_row["created_at"],
            "active": active,
        },
        "history": (
            {
                "occurrences_count": hist_row["occurrences_count"],
                "last_seen": hist_row["last_seen"],
            }
            if hist_row
            else None
        ),
    }


# ── Import from URL ───────────────────────────────────────────────────────────

def import_from_url(
    url: str,
    data_type: str,
    entry_type: str,
    expires_at: Optional[str],
    source: str,
    comment: Optional[str],
) -> dict:
    """
    Download a plain-text threat feed (one entry per line) and bulk-insert.
    INSERT OR IGNORE — existing entries are not modified.
    Does NOT touch threat_history (bulk imports should not inflate counters).
    Returns stats dict.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatFeedService/2.1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise RuntimeError(f"Download failed for {url!r}: {exc}") from exc

    entries: list[tuple[str, str]] = []
    invalid = 0

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        # Strip inline comments (e.g. "1.2.3.4 ; some remark")
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue

        if data_type in ("ip", "cidr"):
            try:
                if "/" in line:
                    ipaddress.ip_network(line, strict=False)
                    entries.append((line, "cidr"))
                else:
                    ipaddress.ip_address(line)
                    entries.append((line, "ip"))
            except ValueError:
                invalid += 1
        elif data_type == "domain":
            if _DOMAIN_RE.match(line):
                entries.append((line, "domain"))
            else:
                invalid += 1

    if not entries:
        return {
            "inserted": 0,
            "skipped_duplicate": 0,
            "skipped_invalid": invalid,
            "total_parsed": invalid,
        }

    with _write_db() as conn:
        before = conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0]
        conn.executemany(
            "INSERT OR IGNORE INTO threat_feed "
            "(element, data_type, entry_type, expires_at, source, comment) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(e, dt, entry_type, expires_at, source, comment) for e, dt in entries],
        )
        after = conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0]

    inserted = after - before
    return {
        "inserted": inserted,
        "skipped_duplicate": len(entries) - inserted,
        "skipped_invalid": invalid,
        "total_parsed": len(entries) + invalid,
    }


# ── Seed ──────────────────────────────────────────────────────────────────────

def _detect_type(element: str) -> str:
    if "/" in element:
        try:
            ipaddress.ip_network(element, strict=False)
            return "cidr"
        except ValueError:
            pass
    try:
        ipaddress.ip_address(element)
        return "ip"
    except ValueError:
        return "domain"


def seed_from_file(path: str) -> tuple[int, int]:
    file = Path(path)
    if not file.exists():
        return 0, 0

    entries: list[tuple[str, str]] = []
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.append((line, _detect_type(line)))

    if not entries:
        return 0, 0

    with _write_db() as conn:
        before = conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0]
        conn.executemany(
            "INSERT OR IGNORE INTO threat_feed "
            "(element, data_type, entry_type, expires_at, source, comment) "
            "VALUES (?, ?, 'permanent', NULL, 'seed', NULL)",
            entries,
        )
        after = conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0]

    inserted = after - before
    return inserted, len(entries) - inserted


# ── Stats & history ───────────────────────────────────────────────────────────

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
        total_elements = conn.execute("SELECT COUNT(*) FROM threat_history").fetchone()[0]
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
            "FROM threat_history ORDER BY occurrences_count DESC, last_seen DESC"
        ).fetchall()
    return [dict(r) for r in rows]
