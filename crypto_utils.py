import time
import hashlib
from typing import Tuple, Union

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


PayloadType = Union[str, bytes]


def now_ts() -> int:
    """Return integer Unix timestamp (seconds)."""
    return int(time.time())


def _to_bytes(payload: PayloadType) -> bytes:
    if isinstance(payload, bytes):
        return payload
    return payload.encode("utf-8")


def commit_payload(payload: PayloadType) -> str:
    """
    Commitment to the raw payload (model input/output).
    This is *not* the chain hash, just a fingerprint of the content.
    """
    pb = _to_bytes(payload)
    h = hashlib.blake2b(digest_size=32)
    h.update(pb)
    return h.hexdigest()


def hash_payload(model_id: str, index: int, prev_hash: str, payload: PayloadType, ts: int) -> str:
    """
    Deterministic hash over all event fields *except* the signature.

    event_hash = H(model_id || index || prev_hash || payload || ts)
    """
    pb = _to_bytes(payload)
    h = hashlib.blake2b(digest_size=32)
    h.update(model_id.encode("utf-8"))
    h.update(b"|")
    h.update(str(index).encode("utf-8"))
    h.update(b"|")
    h.update(prev_hash.encode("utf-8"))
    h.update(b"|")
    h.update(pb)
    h.update(b"|")
    h.update(str(ts).encode("utf-8"))
    return h.hexdigest()


def generate_keypair() -> Tuple[SigningKey, VerifyKey]:
    """Generate a new Ed25519 keypair."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    return sk, vk


def sign_event(message_bytes: bytes, sk: SigningKey) -> bytes:
    """Return signature over canonical message bytes."""
    return sk.sign(message_bytes).signature


def verify_signature(vk: VerifyKey, message_bytes: bytes, signature: bytes) -> bool:
    """Return True if signature is valid for message_bytes under vk."""
    try:
        vk.verify(message_bytes, signature)
        return True
    except BadSignatureError:
        return False
