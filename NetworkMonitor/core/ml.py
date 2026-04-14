# NetworkMonitor/core/ml.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import joblib
from sklearn.ensemble import IsolationForest


@dataclass
class MLConfig:
    contamination: float = 0.005
    n_estimators: int = 50
    train_size: int = 500


class MLDetector:
    """
    Отвечает только за ML:
    - буфер обучения
    - fit/predict
    - save/load модели
    """
    def __init__(self, model_path: Path, cfg: Optional[MLConfig] = None):
        self.cfg = cfg or MLConfig()
        self.model_path = model_path

        self.model = IsolationForest(
            contamination=self.cfg.contamination,
            n_estimators=self.cfg.n_estimators,
            random_state=42
        )
        self.is_trained: bool = False
        self.train_buffer: List[List[float]] = []
        self.vector_size: Optional[int] = None

        # попытка загрузить модель при старте
        self.load()

    def rebuild_model(self) -> None:
        """Пересоздать модель под текущий cfg (когда меняем профиль)."""
        self.model = IsolationForest(
            contamination=self.cfg.contamination,
            n_estimators=self.cfg.n_estimators,
            random_state=42
        )
        self.is_trained = False
        self.train_buffer = []
        self.vector_size = None

    def add_train_sample(self, x: List[float]) -> int:
        if self.vector_size is None:
            self.vector_size = len(x)
        if len(x) != self.vector_size:
            return len(self.train_buffer)
        self.train_buffer.append(x)
        return len(self.train_buffer)

    def can_train(self) -> bool:
        return len(self.train_buffer) >= self.cfg.train_size

    def train(self) -> None:
        self.model.fit(self.train_buffer)
        self.is_trained = True
        self.save()

    def predict_is_anomaly(self, x: List[float]) -> bool:
        if not self.is_trained:
            return False
        expected = getattr(self.model, "n_features_in_", None)
        if expected is not None and len(x) != int(expected):
            return False
        pred = self.model.predict([x])[0]
        return pred == -1

    def save(self) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"model": self.model, "is_trained": self.is_trained, "cfg": self.cfg},
            self.model_path
        )

    def load(self) -> None:
        if not self.model_path.exists():
            return
        try:
            data = joblib.load(self.model_path)
            self.model = data.get("model", self.model)
            self.is_trained = bool(data.get("is_trained", False))
            cfg = data.get("cfg")
            if cfg:
                self.cfg = cfg
            self.vector_size = getattr(self.model, "n_features_in_", None)
        except Exception:
            self.is_trained = False
            self.train_buffer = []
            self.vector_size = None
