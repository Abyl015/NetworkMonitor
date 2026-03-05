from dataclasses import dataclass
from pathlib import Path
import pickle

try:
    from sklearn.ensemble import IsolationForest as _IsolationForest
except ModuleNotFoundError:
    _IsolationForest = None

try:
    import joblib as _joblib
except ModuleNotFoundError:
    _joblib = None


class _FallbackIsolationForest:
    def __init__(self, contamination: float, n_estimators: int):
        self.contamination = contamination
        self.n_estimators = n_estimators

    def fit(self, data):
        return self

    def predict(self, rows):
        return [1 for _ in rows]


@dataclass
class MLConfig:
    train_size: int = 500
    contamination: float = 0.005
    n_estimators: int = 50


class MLDetector:
    def __init__(self, config: MLConfig, model_path: Path):
        self.config = config
        self.model_path = Path(model_path)
        model_cls = _IsolationForest or _FallbackIsolationForest
        self.model = model_cls(
            contamination=self.config.contamination,
            n_estimators=self.config.n_estimators,
        )
        self.is_trained = False

    def _dump(self, obj):
        if _joblib is not None:
            _joblib.dump(obj, self.model_path)
            return
        with open(self.model_path, "wb") as fh:
            pickle.dump(obj, fh)

    def _load(self):
        if _joblib is not None:
            return _joblib.load(self.model_path)
        with open(self.model_path, "rb") as fh:
            return pickle.load(fh)

    def load(self) -> bool:
        if not self.model_path.exists():
            self.is_trained = False
            return False

        self.model = self._load()
        self.is_trained = True
        return True

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self._dump(self.model)

    def fit(self, train_buffer: list[list[float]]) -> bool:
        if len(train_buffer) < self.config.train_size:
            return False
        self.model.fit(train_buffer)
        self.is_trained = True
        self.save()
        return True

    def predict(self, features: list[float]) -> int:
        if not self.is_trained:
            return 1
        return int(self.model.predict([features])[0])
