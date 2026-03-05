# NetworkMonitor/config/profile_manager.py
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List


@dataclass
class Profile:
    filename: str
    data: Dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.data.get("name", self.filename))


class ProfileManager:
    def __init__(self):
        base = Path(__file__).resolve().parent
        self.profiles_dir = base / "profiles"
        self.settings_path = base / "settings.json"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

        # гарантируем наличие default.json
        self._ensure_default_profile()

    # ---------- Public API ----------
    def list_profiles(self) -> List[Profile]:
        profiles: List[Profile] = []
        for p in sorted(self.profiles_dir.glob("*.json")):
            data = self._safe_load_json(p)
            if isinstance(data, dict) and data:
                profiles.append(Profile(filename=p.name, data=data))
        return profiles

    def get_active_filename(self) -> str:
        # settings тоже иногда бывает с BOM, поэтому utf-8-sig
        if self.settings_path.exists():
            s = self._safe_load_json(self.settings_path)
            if isinstance(s, dict):
                return str(s.get("active_profile", "default.json"))
        return "default.json"

    def set_active_filename(self, filename: str) -> None:
        self.settings_path.write_text(
            json.dumps({"active_profile": filename}, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def load_profile(self, filename: str) -> Profile:
        p = self.profiles_dir / filename
        if not p.exists():
            # если запросили несуществующий — откатываемся на default
            p = self.profiles_dir / "default.json"

        data = self._safe_load_json(p)
        if not isinstance(data, dict) or not data:
            # если файл пустой/битый — отдаём дефолт
            data = self._default_profile_dict()

        return Profile(filename=p.name, data=data)

    # ---------- Internal helpers ----------
    def _safe_load_json(self, path: Path) -> Dict[str, Any] | Any:
        try:
            # ключевое: utf-8-sig проглатывает BOM
            text = path.read_text(encoding="utf-8-sig")
            if not text.strip():
                return {}
            return json.loads(text)
        except Exception:
            return {}

    def _ensure_default_profile(self) -> None:
        p = self.profiles_dir / "default.json"
        if not p.exists():
            p.write_text(
                json.dumps(self._default_profile_dict(), ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

    def _default_profile_dict(self) -> Dict[str, Any]:
        # Можешь тут настроить значения “по умолчанию”
        return {
            "name": "Default",
            "sample_factor": 20,
            "pps_window_sec": 10,
            "scan_ports_threshold": 50,
            "dos_pps_eff_threshold": 100,
            "ml": {
                "train_size": 500,
                "contamination": 0.005,
                "n_estimators": 50
            }
        }
