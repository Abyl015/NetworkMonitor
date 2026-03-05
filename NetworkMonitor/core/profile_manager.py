from __future__ import annotations

from .profile import Profile


class ProfileManager:
    def __init__(self):
        self._profiles = {
            "default": Profile(
                name="default",
                data={
                    "sample_factor": 20,
                    "thresholds": {"burst": 10},
                    "ml": {"train_size": 500, "contamination": 0.005, "n_estimators": 50},
                },
            ),
            "strict": Profile(
                name="strict",
                data={
                    "sample_factor": 10,
                    "thresholds": {"burst": 5},
                    "ml": {"train_size": 300, "contamination": 0.01, "n_estimators": 100},
                },
            ),
        }
        self._active_profile_name = "default"

    def names(self) -> list[str]:
        return list(self._profiles.keys())

    def get(self, profile_name: str) -> Profile:
        return self._profiles[profile_name]

    def set_active(self, profile_name: str) -> Profile:
        profile = self.get(profile_name)
        self._active_profile_name = profile.name
        return profile

    def get_active_profile(self) -> Profile:
        return self.get(self._active_profile_name)
