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
            p = self.profiles_dir / "default.json"

        data = self._safe_load_json(p)
        if not isinstance(data, dict) or not data:
            data = self._default_profile_dict()

        return Profile(filename=p.name, data=data)

    def save_profile(self, filename: str, data: Dict[str, Any]) -> None:
        p = self.profiles_dir / filename
        p.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def create_copy(self, src_filename: str, new_filename: str) -> str:
        src = self.load_profile(src_filename)
        # гарантируем .json
        if not new_filename.lower().endswith(".json"):
            new_filename += ".json"

        # если такой уже есть — добавим суффикс
        target = self.profiles_dir / new_filename
        if target.exists():
            stem = target.stem
            i = 2
            while (self.profiles_dir / f"{stem}_{i}.json").exists():
                i += 1
            new_filename = f"{stem}_{i}.json"

        data = dict(src.data)
        data["name"] = f"{src.name} (copy)"
        self.save_profile(new_filename, data)
        return new_filename

    def delete_profile(self, filename: str) -> None:
        # default нельзя удалять
        if filename == "default.json":
            raise ValueError("Нельзя удалить default.json")
        p = self.profiles_dir / filename
        if p.exists():
            p.unlink()

        # если удалили активный — откат на default
        if self.get_active_filename() == filename:
            self.set_active_filename("default.json")

    # ---------- Internal helpers ----------
    def _safe_load_json(self, path: Path) -> Dict[str, Any] | Any:
        try:
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