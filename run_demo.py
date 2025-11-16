from nacl.signing import VerifyKey

from controller import Controller
from crypto_utils import verify_signature
from lineage import LineageStore, Event
from models import HonestModel, AttackerModel


def verify_event(ev: Event, vk: VerifyKey, controller: Controller, phase: str, verbose=True) -> bool:
    ok = verify_signature(vk, ev.canonical_bytes(), ev.signature)
    controller.update(ev.model_id, ok)
    w, t = controller.get(ev.model_id)
    status = "GOOD" if ok else "BAD"

    if verbose:
        print(
            f"[{phase:9s}] idx={ev.index:03d} | {ev.model_id:10s} | {status} | "
            f"w={w/1000:.2f}, θ={t/100:.2f}"
        )

    return ok




def main():
    # Fresh store + controller
    store = LineageStore()
    controller = Controller()

    honest = HonestModel("honest_core")
    attacker = AttackerModel("attacker")

    # ---------------- PHASE 1: BOOTSTRAP (all honest) ---------------- #
    print("=== PHASE 1: BOOTSTRAP ===")
    for i in range(3):
        e1 = honest.make_event(store, f"bootstrap_honest_{i}")
        store.append(e1)
        verify_event(e1, honest.verify_key, controller, "BOOTSTRAP")

        e2 = attacker.make_event(store, f"bootstrap_attack_{i}")
        store.append(e2)
        verify_event(e2, attacker.verify_key, controller, "BOOTSTRAP")

    # ---------------- PHASE 2: ATTACKER MISBEHAVES ---------------- #
    print("\n=== PHASE 2: ATTACKER MISBEHAVES ===")
    for i in range(6):
        # honest continues being honest
        e3 = honest.make_event(store, f"honest_phase2_{i}")
        store.append(e3)
        verify_event(e3, honest.verify_key, controller, "ATTACK")

        # attacker cheats on even i, honest on odd i
        cheat = (i % 2 == 0)
        e4 = attacker.make_event(store, f"malicious_{i}", cheat=cheat)
        store.append(e4)
        verify_event(e4, attacker.verify_key, controller, "ATTACK")

    print("\n=== SUMMARY AFTER PHASE 2 ===")
    controller.summary()

    # ---------------- PHASE 3: RELOAD + REVERIFY ---------------- #
    print("\n=== RELOAD + REVERIFY ===")
    store2 = LineageStore()  # new instance reading same DB
    controller2 = Controller()

    for model, vk in [(honest, honest.verify_key), (attacker, attacker.verify_key)]:
        chain = store2.get_chain(model.model_id)
        for ev in chain:
            verify_event(ev, vk, controller2, "RELOAD")

    print("\n=== SUMMARY AFTER RELOAD ===")
    controller2.summary()

    # Show DB file path
    cur = store2.conn.execute("PRAGMA database_list;")
    row = cur.fetchone()
    if row is not None and len(row) >= 3:
        print(f"\n(DB in {row[2]})")


if __name__ == "__main__":
    main()
