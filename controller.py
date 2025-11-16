class Controller:
    """
    Fixed-point reputation controller.

    - weight in [0, 1000]  (0.00 – 1.00)
    - theta  in [50,  500] (0.50 – 5.00)

    GOOD event:
      weight += 30   (up to 1000)
      theta  -= 8    (down to 50)

    BAD event:
      weight -= 100  (down to 0)
      theta  += 30   (up to 500)
    """

    def __init__(self):
        self.state: dict[str, dict[str, int]] = {}

    def _ensure(self, model_id: str) -> None:
        if model_id not in self.state:
            self.state[model_id] = {"weight": 1000, "theta": 500}

    def update(self, model_id: str, valid: bool) -> None:
        self._ensure(model_id)
        m = self.state[model_id]

        if valid:
            m["weight"] = min(1000, m["weight"] + 30)
            m["theta"] = max(50,   m["theta"]  - 8)
        else:
            m["weight"] = max(0,   m["weight"] - 100)
            m["theta"]  = min(500, m["theta"]  + 30)

    def get(self, model_id: str) -> tuple[int, int]:
        self._ensure(model_id)
        m = self.state[model_id]
        return m["weight"], m["theta"]

    def summary(self) -> None:
        print("\n=== FINAL CONTROLLER SUMMARY ===")
        for mid, m in sorted(self.state.items()):
            w = m["weight"] / 1000.0
            t = m["theta"]  / 100.0
            print(f"{mid:12s} | weight={w:.2f}, theta={t:.2f}")
