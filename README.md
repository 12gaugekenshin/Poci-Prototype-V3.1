Proof-Of-Compute-Integrity Prototype
---
You must READ the HOW TO RUN PROTOTYPE for this branch in order to run this prototype!

Fixes Include from V2:

• Added Payload Commitment Raw event payloads now get a BLAKE2b commitment (payload_commit) to prevent tampering and bind proofs to real data.

• Canonical Serialization for Signing All signatures now use a single deterministic byte-format for both signing and verification.

• SQLite Lineage Database Every event is persisted with id, timestamp, parent, payload hash, signature, and results for full lineage reconstruction.

• Improved Weight/Trust Controller GOOD/BAD updates are now symmetric, stable, and resistant to drift, giving cleaner honest/attacker separation.

• Structured Reason Codes Validation now reports explicit reasons (OK, SIGNATURE_INVALID, PAYLOAD_MISMATCH, ATTACK_BEHAVIOR, etc.).

• Modular Attack Models Attacker logic refactored into clean classes so different adversaries (timing, drift, mutators, etc.) can be plugged in easily.

• Full Verifier Rebuild Verifier now re-derives signatures, payloads, and lineage from the database instead of trusting anything in memory.
