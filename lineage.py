import sqlite3
from dataclasses import dataclass
from typing import List, Optional

from crypto_utils import commit_payload, hash_payload, now_ts


GENESIS = "0" * 64
DB_PATH = "poc_integrity.db"


# ============================
#   EVENT STRUCTURE
# ============================

@dataclass
class Event:
    model_id: str
    index: int
    ts: int
    payload: str
    payload_hash: str
    payload_commit: str
    prev_hash: str
    event_hash: str
    signature: bytes

    def canonical_bytes(self) -> bytes:
        """
        Canonical serialization used for signing and verification.
        This must stay stable over time.
        """
        return f"{self.model_id}|{self.index}|{self.prev_hash}|{self.event_hash}|{self.payload_commit}|{self.ts}".encode(
            "utf-8"
        )


# ============================
#   DB INIT
# ============================

def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            idx            INTEGER PRIMARY KEY,
            model_id       TEXT NOT NULL,
            ts             INTEGER NOT NULL,
            payload        TEXT NOT NULL,
            payload_hash   TEXT NOT NULL,
            payload_commit TEXT NOT NULL,
            prev_hash      TEXT NOT NULL,
            event_hash     TEXT NOT NULL,
            signature      BLOB NOT NULL
        )
        """
    )
    conn.commit()
    return conn


# ============================
#   LINEAGE STORE
# ============================

class LineageStore:
    """
    SQLite-backed store for events.
    - Global monotonic index (idx) across all models.
    - Per-model prev_hash continuity.
    - Durable across restarts.
    """

    def __init__(self, autocommit=True):
        self.conn = _init_db()
        self.autocommit = autocommit
        self._pending = 0  # batch commit counter

    # --------- index / hash helpers --------- #

    def next_index(self) -> int:
        cur = self.conn.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM events")
        (val,) = cur.fetchone()
        return int(val)

    def last_hash(self, model_id: str) -> str:
        cur = self.conn.execute(
            """
            SELECT event_hash FROM events
            WHERE model_id = ?
            ORDER BY idx DESC LIMIT 1
            """,
            (model_id,),
        )
        row = cur.fetchone()
        return row[0] if row else GENESIS

    def last_ts(self, model_id: str) -> Optional[int]:
        cur = self.conn.execute(
            """
            SELECT ts FROM events
            WHERE model_id = ?
            ORDER BY idx DESC LIMIT 1
            """,
            (model_id,),
        )
        row = cur.fetchone()
        return int(row[0]) if row else None

    # --------- event persistence --------- #

    def append(self, ev: Event) -> None:
        """
        Append an event to the store.
        Enforces:
        - prev_hash must match last_hash(model_id)
        - idx must be the next global index
        """

        expected_idx = self.next_index()
        if ev.index != expected_idx:
            raise ValueError(
                f"Index mismatch: ev.index={ev.index}, expected={expected_idx}"
            )

        expected_prev = self.last_hash(ev.model_id)
        if ev.prev_hash != expected_prev:
            raise ValueError(
                f"prev_hash mismatch for {ev.model_id}: {ev.prev_hash} != {expected_prev}"
            )

        # Insert into DB
        self.conn.execute(
            """
            INSERT INTO events (
                idx, model_id, ts, payload, payload_hash,
                payload_commit, prev_hash, event_hash, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ev.index,
                ev.model_id,
                ev.ts,
                ev.payload,
                ev.payload_hash,
                ev.payload_commit,
                ev.prev_hash,
                ev.event_hash,
                ev.signature,
            ),
        )

        # Batch commit every 1000 inserts
        self._pending += 1
        if self.autocommit and self._pending >= 1000:
            self.conn.commit()
            self._pending = 0

    # --------- chain access --------- #

    def get_chain(self, model_id: str) -> List[Event]:
        cur = self.conn.execute(
            """
            SELECT model_id, idx, ts, payload, payload_hash,
                   payload_commit, prev_hash, event_hash, signature
            FROM events
            WHERE model_id = ?
            ORDER BY idx
            """,
            (model_id,),
        )
        rows = cur.fetchall()
        return [Event(*row) for row in rows]

    def all_events(self) -> List[Event]:
        cur = self.conn.execute(
            """
            SELECT model_id, idx, ts, payload, payload_hash,
                   payload_commit, prev_hash, event_hash, signature
            FROM events
            ORDER BY idx
            """
        )
        return [Event(*row) for row in cur.fetchall()]


# ============================
#   REBUILD HELPER
# ============================

def rebuild_event(
    model_id: str,
    index: int,
    payload: str,
    prev_hash: str,
    ts: int,
    signature: bytes,
) -> Event:
    """
    Helper to build a fully consistent Event from raw pieces.
    Used by models and tests.
    """
    payload_commit = commit_payload(payload)
    ev_hash = hash_payload(model_id, index, prev_hash, payload, ts)
    payload_hash = ev_hash  # unified

    return Event(
        model_id=model_id,
        index=index,
        ts=ts,
        payload=payload,
        payload_hash=payload_hash,
        payload_commit=payload_commit,
        prev_hash=prev_hash,
        event_hash=ev_hash,
        signature=signature,
    )
