from typing import Optional

from nacl.signing import SigningKey, VerifyKey

from crypto_utils import generate_keypair, now_ts, commit_payload, hash_payload, sign_event
from lineage import Event, LineageStore


class BaseModel:
    """
    Base model/agent that can emit PoCI events.

    - Each model has its own Ed25519 keypair.
    - Timestamps are enforced to be monotonic per model instance.
    """

    def __init__(self, model_id: str):
        self.model_id = model_id
        self.sk, self.vk = generate_keypair()
        self._last_ts: int = 0

    @property
    def verify_key(self) -> VerifyKey:
        return self.vk

    def _next_ts(self, store: LineageStore) -> int:
        """
        Monotonic timestamp per model.

        Uses max(current_time, last_ts + 1, last_ts_in_db + 1)
        so that restarts can't go backwards.
        """
        now = now_ts()
        # Look at persisted chain too
        last_db_ts: Optional[int] = store.last_ts(self.model_id)
        candidate = max(
            now,
            self._last_ts + 1,
            (last_db_ts + 1) if last_db_ts is not None else 0,
        )
        self._last_ts = candidate
        return candidate

    def make_event(self, store: LineageStore, payload: str, cheat: bool = False) -> Event:
        """
        Create a new event for this model.
        - idx = global index from store
        - prev_hash = last_hash(model_id)
        - ts = monotonic timestamp
        - payload_commit & event_hash computed canonically
        - cheat=True: signs reversed canonical bytes → invalid signature
        """
        idx = store.next_index()
        prev = store.last_hash(self.model_id)
        ts = self._next_ts(store)

        # Build canonical event fields
        payload_commit = commit_payload(payload)
        ev_hash = hash_payload(self.model_id, idx, prev, payload, ts)
        payload_hash = ev_hash  # unified

        # Build canonical bytes for signing
        canonical = f"{self.model_id}|{idx}|{prev}|{ev_hash}|{payload_commit}|{ts}".encode(
            "utf-8"
        )
        message_bytes = canonical if not cheat else canonical[::-1]
        sig = sign_event(message_bytes, self.sk)

        return Event(
            model_id=self.model_id,
            index=idx,
            ts=ts,
            payload=payload,
            payload_hash=payload_hash,
            payload_commit=payload_commit,
            prev_hash=prev,
            event_hash=ev_hash,
            signature=sig,
        )


class HonestModel(BaseModel):
    """Always signs honestly."""
    pass


class AttackerModel(BaseModel):
    """
    Attacker model.
    Has a mutate_event hook so stress tests can inject behaviors.
    """
    def mutate_event(self, ev):
        # Default: do nothing. Stress harness can monkeypatch or subclass this.
        return ev

    def make_event(self, store: LineageStore, payload: str, cheat: bool = False) -> Event:
        # Call BaseModel's event creation
        ev = super().make_event(store, payload, cheat)

        # Allow attacker behaviors to mutate the event after creation
        return self.mutate_event(ev)

