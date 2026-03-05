import re
from collections import Counter
from pathlib import Path
from typing import Any

from .ml import MLConfig, MLDetector
from .profile import Profile
from .rules import RuleEngine


class Engine:
    def __init__(self, profile: Profile | None = None):
        self.profile_name = "default"
        self.profile_data: dict[str, Any] = {}
        self.total_seen = 0
        self.total_anom = 0
        self.attacker_stats = Counter()
        self.packet_count = 0
        self.train_buffer: list[list[float]] = []

        self.rules = RuleEngine()
        self.ml = self._build_ml(self.profile_name, self.profile_data)

        if profile is not None:
            self.apply_profile(profile)

    @staticmethod
    def _safe_profile_name(profile_name: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", (profile_name or "default").strip())
        return safe or "default"

    def _model_path_for(self, profile_name: str) -> Path:
        safe_name = self._safe_profile_name(profile_name)
        base = Path(__file__).resolve().parents[1] / "storage" / "models"
        return base / f"model_{safe_name}.joblib"

    def _build_ml(self, profile_name: str, data: dict[str, Any]) -> MLDetector:
        ml_data = data.get("ml", {}) if isinstance(data, dict) else {}
        config = MLConfig(
            train_size=int(ml_data.get("train_size", 500)),
            contamination=float(ml_data.get("contamination", 0.005)),
            n_estimators=int(ml_data.get("n_estimators", 50)),
        )
        detector = MLDetector(config=config, model_path=self._model_path_for(profile_name))
        detector.load()
        return detector

    def _build_rules(self, data: dict[str, Any]) -> RuleEngine:
        return RuleEngine(
            sample_factor=int(data.get("sample_factor", 20)),
            thresholds=data.get("thresholds", {}),
        )

    def apply_profile(self, profile_obj: Profile) -> None:
        self.profile_name = profile_obj.name
        self.profile_data = dict(profile_obj.data or {})
        self.rules = self._build_rules(self.profile_data)
        self.ml = self._build_ml(self.profile_name, self.profile_data)
        self.ml.load()

    def reset_state(self) -> None:
        self.total_seen = 0
        self.total_anom = 0
        self.attacker_stats = Counter()
        self.packet_count = 0
        self.train_buffer = []
        self.rules = self._build_rules(self.profile_data)
