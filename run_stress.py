"""
PoCI V3 – Mega Stress Test Harness

This script hammers the V3 engine with a large number of events, mixed
honest + attacker models, and multiple adversarial behaviors.

It:
  - generates a long event sequence (configurable)
  - injects different attacker strategies
  - verifies each event with:
        * signature check
        * payload_commit check
        * event_hash recomputation
  - updates the Controller for every event
  - prints a compact summary + anomaly stats at the end
"""

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from nacl.signing import VerifyKey

from controller import Controller
from crypto_utils import (
    commit_payload,
    hash_payload,
    verify_signature,
)
from lineage import LineageStore, Event
from models import HonestModel, AttackerModel


# ============================
#   CONFIG
# ============================

TOTAL_EVENTS = 100_000      # you can bump this to 500_000 or 1_000_000+
NUM_HONEST = 8
NUM_SIG_CHEAT_ATTACKERS = 4
NUM_COMMIT_DRIFT_ATTACKERS = 4
NUM_SLOW_DRIP_ATTACKERS = 4

ATTACKER_EVENT_RATE = 0.35  # probability that a given event is from an attacker


# ============================
#   STATS
# ============================

@dataclass
class AnomalyStats:
    total_events: int = 0
    honest_events: int = 0
    attacker_events: int = 0

    sig_invalid: int = 0
    commit_mismatch: int = 0
    eventhash_mismatch: int = 0

    bad_events: int = 0  # any of the above triggered

    per_model_bad: Dict[str, int] = field(default_factory=dict)

    def mark_bad(self, model_id: str):
        self.bad_events += 1
        self.per_model_bad[model_id] = self.per_model_bad.get(model_id, 0) + 1


# ============================
#   ATTACKER VARIANTS
# ============================

class SigCheatAttacker(AttackerModel):
    """
    Occasionally uses cheat=True (reversed canonical bytes before signing),
    producing invalid signatures while leaving structure intact.
    """

    def __init__(self, model_id: str, cheat_rate: float = 0.3):
        super().__init__(model_id)
        self.cheat_rate = cheat_rate

    def make_event(self, store: LineageStore, payload: str, cheat: bool = False) -> Event:
        use_cheat = (random.random() < self.cheat_rate)
        ev = super().make_event(store, payload, cheat=use_cheat)
        return self.mutate_event(ev)


class CommitDriftAttacker(AttackerModel):
    """
    Sometimes corrupts payload_commit or event_hash after honest creation,
    creating structural mismatches that a proper verifier should catch.
    """

    def __init__(self, model_id: str, drift_rate: float = 0.4):
        super().__init__(model_id)
        self.drift_rate = drift_rate

    def mutate_event(self, ev: Event) -> Event:
        # Mostly honest, sometimes malicious.
        if random.random() >= self.drift_rate:
            return ev

        mode = random.choice(["payload_commit_only", "event_hash_only", "both"])
        # Do NOT touch index or prev_hash (or model_id / ts) to keep DB constraints valid.
        if mode in ("payload_commit_only", "both"):
            # Corrupt the commitment (does not match the real payload anymore)
            ev.payload_commit = "DEAD" * 16  # 64 hex chars

        if mode in ("event_hash_only", "both"):
            # Corrupt the event hash (no longer equal to canonical recompute)
            ev.event_hash = "BEEF" * 16
            ev.payload_hash = ev.event_hash  # keep the unified assumption

        return ev


class SlowDripAttacker(AttackerModel):
    """
    Very sneaky: misbehaves rarely, trying to survive in the system
    while introducing long-tail corruption.
    """

    def __init__(self, model_id: str, drip_rate: float = 0.02):
        super().__init__(model_id)
        self.drip_rate = drip_rate

    def mutate_event(self, ev: Event) -> Event:
        # 98% of the time: honest
        if random.random() >= self.drip_rate:
            return ev

        # 2% of the time: subtle corruption – tweak payload but leave metadata as-is
        ev.payload = ev.payload + "_shadow"
        # Don't update payload_commit or event_hash → structural mismatch
        return ev


# ============================
#   VERIFICATION LOGIC
# ============================

def verify_event_full(ev: Event, vk: VerifyKey, controller: Controller, stats: AnomalyStats) -> bool:
    """
    Stronger verification than the basic demo:
      - signature check
      - payload_commit recomputation
      - event_hash recomputation
    """
    stats.total_events += 1

    # Recompute commit and event hash from the stored fields
    recomputed_commit = commit_payload(ev.payload)
    commit_ok = (recomputed_commit == ev.payload_commit)

    recomputed_eh = hash_payload(ev.model_id, ev.index, ev.prev_hash, ev.payload, ev.ts)
    eventhash_ok = (recomputed_eh == ev.event_hash and ev.payload_hash == ev.event_hash)

    sig_ok = verify_signature(vk, ev.canonical_bytes(), ev.signature)

    if not sig_ok:
        stats.sig_invalid += 1
    if not commit_ok:
        stats.commit_mismatch += 1
    if not eventhash_ok:
        stats.eventhash_mismatch += 1

    ok = sig_ok and commit_ok and eventhash_ok
    controller.update(ev.model_id, ok)

    if not ok:
        stats.mark_bad(ev.model_id)

    return ok


# ============================
#   MAIN STRESS DRIVER
# ============================

def run_stress():
    print("=== PoCI V3 MEGA STRESS TEST ===")
    print(f"TOTAL_EVENTS={TOTAL_EVENTS}")
    print(f"NUM_HONEST={NUM_HONEST}, "
          f"SIG_CHEAT_ATTACKERS={NUM_SIG_CHEAT_ATTACKERS}, "
          f"COMMIT_DRIFT_ATTACKERS={NUM_COMMIT_DRIFT_ATTACKERS}, "
          f"SLOW_DRIP_ATTACKERS={NUM_SLOW_DRIP_ATTACKERS}")
    print(f"ATTACKER_EVENT_RATE={ATTACKER_EVENT_RATE}")
    print("--------------------------------------------------")

    start_time = time.time()

    # Use autocommit batching as configured in LineageStore
    store = LineageStore(autocommit=True)
    controller = Controller()
    stats = AnomalyStats()

    # Honest models
    honest_models: List[HonestModel] = [
        HonestModel(f"honest_{i:02d}") for i in range(NUM_HONEST)
    ]

    # Attacker models with different behaviors
    attackers: List[AttackerModel] = []

    for i in range(NUM_SIG_CHEAT_ATTACKERS):
        attackers.append(SigCheatAttacker(f"att_sig_{i:02d}", cheat_rate=0.3))

    for i in range(NUM_COMMIT_DRIFT_ATTACKERS):
        attackers.append(CommitDriftAttacker(f"att_commit_{i:02d}", drift_rate=0.4))

    for i in range(NUM_SLOW_DRIP_ATTACKERS):
        attackers.append(SlowDripAttacker(f"att_slow_{i:02d}", drip_rate=0.02))

    # Map model_id -> verify_key for quick lookup if needed
    vk_map: Dict[str, VerifyKey] = {}
    for m in honest_models + attackers:
        vk_map[m.model_id] = m.verify_key

    # ------------- MAIN LOOP ------------- #
    for step in range(TOTAL_EVENTS):
        use_attacker = (random.random() < ATTACKER_EVENT_RATE)

        if use_attacker and attackers:
            m = random.choice(attackers)
            stats.attacker_events += 1
            payload = f"stress_attack_step_{step}"
        else:
            m = random.choice(honest_models)
            stats.honest_events += 1
            payload = f"stress_honest_step_{step}"

        # Create event (attackers might internally mutate)
        ev = m.make_event(store, payload)
        # Append to DB (with batched commits)
        store.append(ev)
        # Verify with full checks
        verify_event_full(ev, m.verify_key, controller, stats)

        # Optional: print periodic progress
        if (step + 1) % 10_000 == 0:
            elapsed = time.time() - start_time
            print(f"[PROGRESS] {step+1}/{TOTAL_EVENTS} events | elapsed={elapsed:.1f}s")

    # Final commit flush
    store.conn.commit()

    elapsed_total = time.time() - start_time

    print("\n=== STRESS TEST COMPLETE ===")
    print(f"Total time: {elapsed_total:.2f} s")
    print(f"Events/sec: {TOTAL_EVENTS / max(elapsed_total, 1e-6):.1f}")
    print("--------------------------------------------------")

    print(f"Total events:       {stats.total_events}")
    print(f"  Honest events:    {stats.honest_events}")
    print(f"  Attacker events:  {stats.attacker_events}")
    print()
    print(f"Invalid signatures: {stats.sig_invalid}")
    print(f"Commit mismatches:  {stats.commit_mismatch}")
    print(f"Event hash errors:  {stats.eventhash_mismatch}")
    print(f"Total BAD events:   {stats.bad_events}")

    print("\n=== CONTROLLER SUMMARY (POST-STRESS) ===")
    controller.summary()

    # Optionally: list the worst offenders
    if stats.per_model_bad:
        print("\n=== TOP OFFENDING MODELS ===")
        sorted_bad: List[Tuple[str, int]] = sorted(
            stats.per_model_bad.items(), key=lambda kv: kv[1], reverse=True
        )
        for mid, cnt in sorted_bad[:10]:
            print(f"{mid:16s} | bad_events={cnt}")


    # ------------- OPTIONAL: RELOAD + RECHECK ------------- #
    print("\n=== RELOAD + REVERIFY SAMPLE ===")
    store2 = LineageStore()  # re-open same DB
    controller2 = Controller()
    stats2 = AnomalyStats()

    # Re-verify only attacker chains (worst-case)
    for att in attackers:
        chain = store2.get_chain(att.model_id)
        for ev in chain:
            verify_event_full(ev, att.verify_key, controller2, stats2)

    print("\n[Reloaded attacker chains]")
    print(f"  Total attacker events rechecked: {stats2.total_events}")
    print(f"  BAD on reload: {stats2.bad_events}")
    print("\n=== CONTROLLER SUMMARY (RELOAD/ATTACKERS ONLY) ===")
    controller2.summary()


if __name__ == "__main__":
    run_stress()
