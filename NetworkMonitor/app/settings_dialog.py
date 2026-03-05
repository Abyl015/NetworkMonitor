from __future__ import annotations

import json
import re
from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QFormLayout, QSpinBox, QDoubleSpinBox, QMessageBox, QInputDialog
)
from PyQt6.QtCore import Qt

from NetworkMonitor.config.profile_manager import ProfileManager, Profile


def _safe_filename_stem(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^a-z0-9_\-]+", "", s)
    return s or "profile"


def _safe_profile_key(name: str) -> str:
    # должно совпадать с engine._build_ml safe_name
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name)


def _model_path_for_profile(profile_stem: str) -> Path:
    pkg_dir = Path(__file__).resolve().parents[1]  # .../NetworkMonitor
    models_dir = pkg_dir / "storage" / "models"
    return models_dir / f"model_{_safe_profile_key(profile_stem)}.joblib"


class SettingsDialog(QDialog):
    def __init__(self, parent, engine):
        super().__init__(parent)
        self.setWindowTitle("Профили / Настройки")
        self.setMinimumWidth(720)

        self.engine = engine
        self.pm = ProfileManager()
        self.current_profile: Profile | None = None

        root = QVBoxLayout(self)

        # --- row: profile select + apply ---
        top = QHBoxLayout()
        top.addWidget(QLabel("ПРОФИЛЬ:"))

        self.profile_combo = QComboBox()
        top.addWidget(self.profile_combo, stretch=1)

        self.apply_btn = QPushButton("ПРИМЕНИТЬ ПРОФИЛЬ")
        self.apply_btn.clicked.connect(self.apply_profile_clicked)
        top.addWidget(self.apply_btn)

        root.addLayout(top)

        # --- form values ---
        form = QFormLayout()

        self.sample_factor = QSpinBox()
        self.sample_factor.setRange(1, 200)
        form.addRow("Sampling (каждый N-й пакет):", self.sample_factor)

        self.pps_window_sec = QSpinBox()
        self.pps_window_sec.setRange(1, 120)
        form.addRow("Окно PPS (сек):", self.pps_window_sec)

        self.scan_ports_threshold = QSpinBox()
        self.scan_ports_threshold.setRange(1, 10000)
        form.addRow("Порог Port-Scan (уник. порты):", self.scan_ports_threshold)

        self.dos_pps_eff_threshold = QSpinBox()
        self.dos_pps_eff_threshold.setRange(1, 200000)
        form.addRow("Порог DoS (pps_eff):", self.dos_pps_eff_threshold)

        self.train_size = QSpinBox()
        self.train_size.setRange(50, 100000)
        form.addRow("ML train_size (пакетов):", self.train_size)

        self.contamination = QDoubleSpinBox()
        self.contamination.setRange(0.0001, 0.5)
        self.contamination.setDecimals(4)
        self.contamination.setSingleStep(0.001)
        form.addRow("ML contamination:", self.contamination)

        self.n_estimators = QSpinBox()
        self.n_estimators.setRange(10, 1000)
        form.addRow("ML n_estimators:", self.n_estimators)

        root.addLayout(form)

        # --- buttons row ---
        btns = QHBoxLayout()

        self.save_btn = QPushButton("СОХРАНИТЬ ИЗМЕНЕНИЯ")
        self.save_btn.clicked.connect(self.save_clicked)
        btns.addWidget(self.save_btn)

        self.copy_btn = QPushButton("СОЗДАТЬ ПРОФИЛЬ (КОПИЯ)")
        self.copy_btn.clicked.connect(self.copy_clicked)
        btns.addWidget(self.copy_btn)

        self.delete_btn = QPushButton("УДАЛИТЬ ПРОФИЛЬ")
        self.delete_btn.clicked.connect(self.delete_clicked)
        btns.addWidget(self.delete_btn)

        self.reset_ml_btn = QPushButton("СБРОСИТЬ ML МОДЕЛЬ")
        self.reset_ml_btn.clicked.connect(self.reset_ml_clicked)
        btns.addWidget(self.reset_ml_btn)

        root.addLayout(btns)

        # --- signals ---
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)

        # fill
        self.reload_profiles(select_active=True)

    # ---------------------------
    # helpers: filesystem ops
    # ---------------------------
    def _profile_path(self, filename: str) -> Path:
        return self.pm.profiles_dir / filename

    def _read_json_profile(self, filename: str) -> dict:
        p = self._profile_path(filename)
        # BOM-safe
        text = p.read_text(encoding="utf-8-sig")
        return json.loads(text)

    def _write_json_profile(self, filename: str, data: dict) -> None:
        p = self._profile_path(filename)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------------------
    # load/display
    # ---------------------------
    def reload_profiles(self, select_active: bool = False):
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()

        profiles = self.pm.list_profiles()
        for prof in profiles:
            self.profile_combo.addItem(prof.name, prof.filename)

        self.profile_combo.blockSignals(False)

        if select_active:
            active = self.pm.get_active_filename()
            idx = self.profile_combo.findData(active)
            if idx >= 0:
                self.profile_combo.setCurrentIndex(idx)

        self.on_profile_changed()

    def on_profile_changed(self):
        filename = self.profile_combo.currentData()
        if not filename:
            return

        self.current_profile = self.pm.load_profile(filename)
        self.set_form_from_profile(self.current_profile)

        # default profile нельзя удалять
        self.delete_btn.setEnabled(filename != "default.json")

    def set_form_from_profile(self, prof: Profile):
        d = prof.data
        ml = d.get("ml", {}) if isinstance(d.get("ml", {}), dict) else {}

        self.sample_factor.setValue(int(d.get("sample_factor", 20)))
        self.pps_window_sec.setValue(int(d.get("pps_window_sec", 10)))
        self.scan_ports_threshold.setValue(int(d.get("scan_ports_threshold", 50)))
        self.dos_pps_eff_threshold.setValue(int(d.get("dos_pps_eff_threshold", 100)))

        # поддержка старого ключа train_packets
        self.train_size.setValue(int(ml.get("train_size", ml.get("train_packets", 500))))
        self.contamination.setValue(float(ml.get("contamination", 0.005)))
        self.n_estimators.setValue(int(ml.get("n_estimators", 50)))

    def build_profile_dict_from_form(self) -> dict:
        # сохраним имя профиля, если оно есть в json; иначе по filename
        name = "Profile"
        if self.current_profile:
            name = str(self.current_profile.data.get("name", self.current_profile.filename))

        return {
            "name": name,
            "sample_factor": int(self.sample_factor.value()),
            "pps_window_sec": int(self.pps_window_sec.value()),
            "scan_ports_threshold": int(self.scan_ports_threshold.value()),
            "dos_pps_eff_threshold": int(self.dos_pps_eff_threshold.value()),
            "ml": {
                "train_size": int(self.train_size.value()),
                "contamination": float(self.contamination.value()),
                "n_estimators": int(self.n_estimators.value()),
            }
        }

    # ---------------------------
    # actions
    # ---------------------------
    def save_clicked(self):
        if not self.current_profile:
            return
        filename = self.current_profile.filename
        data = self.build_profile_dict_from_form()

        try:
            self._write_json_profile(filename, data)
            QMessageBox.information(self, "Профиль", f"Сохранено: {filename}")
            # обновим данные в UI/списке
            self.reload_profiles(select_active=False)
            idx = self.profile_combo.findData(filename)
            if idx >= 0:
                self.profile_combo.setCurrentIndex(idx)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {type(e).__name__}: {e}")

    def apply_profile_clicked(self):
        if not self.current_profile:
            return
        filename = self.current_profile.filename

        try:
            prof = self.pm.load_profile(filename)

            # применяем в движок
            profile_stem = Path(filename).stem
            self.engine.apply_profile(prof.data, profile_name=profile_stem)

            # делаем активным
            self.pm.set_active_filename(filename)

            QMessageBox.information(self, "Профиль", f"Применён: {prof.name} ({filename})")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось применить: {type(e).__name__}: {e}")

    def copy_clicked(self):
        if not self.current_profile:
            return

        text, ok = QInputDialog.getText(self, "Копия профиля", "Имя нового профиля (без .json):")
        if not ok or not text.strip():
            return

        new_stem = _safe_filename_stem(text)
        new_filename = f"{new_stem}.json"

        # если есть — добавим суффикс
        i = 2
        while self._profile_path(new_filename).exists():
            new_filename = f"{new_stem}_{i}.json"
            i += 1

        try:
            # берём текущие значения (из формы) — удобно
            data = self.build_profile_dict_from_form()
            data["name"] = text.strip()

            self._write_json_profile(new_filename, data)

            QMessageBox.information(self, "Профиль", f"Создан: {new_filename}")
            self.reload_profiles(select_active=False)

            idx = self.profile_combo.findData(new_filename)
            if idx >= 0:
                self.profile_combo.setCurrentIndex(idx)

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать копию: {type(e).__name__}: {e}")

    def delete_clicked(self):
        if not self.current_profile:
            return
        filename = self.current_profile.filename

        if filename == "default.json":
            QMessageBox.warning(self, "Удаление", "Нельзя удалить default.json")
            return

        reply = QMessageBox.question(
            self,
            "Удаление профиля",
            f"Удалить профиль {self.current_profile.name} ({filename})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            p = self._profile_path(filename)
            if p.exists():
                p.unlink()

            # если удалили активный — откатимся на default
            if self.pm.get_active_filename() == filename:
                self.pm.set_active_filename("default.json")

            QMessageBox.information(self, "Удаление", f"Удалено: {filename}")
            self.reload_profiles(select_active=True)

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить: {type(e).__name__}: {e}")

    def reset_ml_clicked(self):
        if not self.current_profile:
            return

        filename = self.current_profile.filename
        profile_stem = Path(filename).stem
        p = _model_path_for_profile(profile_stem)

        reply = QMessageBox.question(
            self,
            "Сброс ML модели",
            f"Удалить ML модель для профиля '{profile_stem}'?\n{p}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            if p.exists():
                p.unlink()
            QMessageBox.information(self, "ML", "Модель удалена. При следующем запуске мониторинга обучится заново.")
        except Exception as e:
            QMessageBox.critical(self, "ML", f"Ошибка удаления: {type(e).__name__}: {e}")