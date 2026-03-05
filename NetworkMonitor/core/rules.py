class RuleEngine:
    def __init__(self, sample_factor: int = 20, thresholds: dict | None = None):
        self.sample_factor = max(1, int(sample_factor))
        self.thresholds = thresholds.copy() if thresholds else {}
        self._state = {}

    def mark(self, key: str) -> int:
        self._state[key] = self._state.get(key, 0) + 1
        return self._state[key]
