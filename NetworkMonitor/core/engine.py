# NetworkMonitor/core/engine.py
from __future__ import annotations

import time
from pathlib import Path
from collections import Counter
from typing import Optional

import scapy.all as scapy

from NetworkMonitor.core.features import extract_features
from NetworkMonitor.core.rules import RuleEngine
from NetworkMonitor.core.scoring import calc_ib_score
from NetworkMonitor.core.ml import MLDetector, MLConfig
from NetworkMonitor.storage.database import init_db, add_alert

scapy.conf.noipaddrs = True


class NetworkEngine:
    def __init__(self, callback):
        self.callback = callback

        # stop control
        self.running: bool = False
        self._sniffer: Optional[scapy.AsyncSniffer] = None

        # stats
        self.attacker_stats = Counter()
        self.packet_count = 0

        # profile-related defaults
        self.sample_factor = 20
        self.profile_name = "default"

        # RULES + SCORE
        self.rules = RuleEngine(sample_factor=self.sample_factor)
        self.total_seen = 0
        self.total_anom = 0
        self.last_ib_score = 100
        self.last_ib_level = "Высокий уровень ИБ"

        # ML detector (separate model per profile)
        self.ml = self._build_ml(profile_name=self.profile_name, ml_cfg=MLConfig())

    # -------------------------
    # Public controls
    # -------------------------
    def stop_capture(self):
        self.running = False
        try:
            if self._sniffer and self._sniffer.running:
                self._sniffer.stop()
        except Exception:
            pass

    def apply_profile(self, profile, profile_name: str = "default"):
        """
        profile может быть dict или Profile(filename, data).
        """
        # поддержка ProfileManager.Profile
        if hasattr(profile, "data"):
            profile_name = getattr(profile, "filename", profile_name) or profile_name
            profile = profile.data

        self.profile_name = profile_name or "default"

        # sampling
        self.sample_factor = int(profile.get("sample_factor", 20))

        # RULES
        self.rules = RuleEngine(
            sample_factor=self.sample_factor,
            pps_window_sec=int(profile.get("pps_window_sec", 10)),
            scan_ports_threshold=int(profile.get("scan_ports_threshold", 50)),
            dos_pps_eff_threshold=int(profile.get("dos_pps_eff_threshold", 100)),
        )

        # ML config
        ml = profile.get("ml", {})
        if not isinstance(ml, dict):
            ml = {}

        train_size = ml.get("train_size", ml.get("train_packets", 500))  # поддержка обоих ключей

        ml_cfg = MLConfig(
            contamination=float(ml.get("contamination", 0.005)),
            n_estimators=int(ml.get("n_estimators", 50)),
            train_size=int(train_size),
        )

        # rebuild detector for this profile (it will auto-load its own model file)
        self.ml = self._build_ml(profile_name=self.profile_name, ml_cfg=ml_cfg)

        # лог статуса модели
        if self.ml.is_trained:
            self._log(f"<b style='color:#a6e3a1;'>[PROFILE] ML модель загружена для профиля: {self.profile_name}</b>")
        else:
            self._log(f"<b style='color:#89dceb;'>[PROFILE] ML будет обучаться заново: {self.profile_name}</b>")

    # -------------------------
    # Capture
    # -------------------------
    def get_working_iface(self):
        interfaces = scapy.get_working_ifaces()
        for iface in interfaces:
            name = (iface.description or "").lower()
            if iface.ip and iface.ip != "127.0.0.1":
                if "bluetooth" not in name and "virtual" not in name:
                    return iface
        return scapy.conf.iface

    def start_capture(self):
        init_db()

        scapy.conf.sniff_promisc = True
        scapy.conf.verbose = False

        active_iface = self.get_working_iface()
        iface_desc = getattr(active_iface, "description", str(active_iface))

        self._log(f"<b style='color:#89b4fa;'>[DEBUG] Активен: {iface_desc}</b>")
        self._log(f"<b style='color:#89b4fa;'>[DEBUG] IP: {getattr(active_iface, 'ip', 'unknown')}</b>")
        self._log(f"<b style='color:#89dceb;'>[SYSTEM] Профиль: {self.profile_name} | sampling=1/{self.sample_factor}</b>")

        if self.ml.is_trained:
            self._log("<b style='color:#a6e3a1;'>[SYSTEM] Модель загружена. Защита АКТИВНА.</b>")
        else:
            self._log(f"<b style='color:#89dceb;'>[SYSTEM] Слушаю эфир... (Нужно {self.ml.cfg.train_size} пакетов)</b>")

        self.running = True

        try:
            self._sniffer = scapy.AsyncSniffer(
                iface=active_iface,
                prn=self.process_packet,
                store=False,
                filter="ip",
            )
            self._sniffer.start()

            while self.running:
                time.sleep(0.2)

        except Exception as e:
            self._log(f"<span style='color:#f38ba8;'>Ошибка захвата: {type(e).__name__}: {e}</span>")
        finally:
            self.stop_capture()
            self._log("<b style='color:#f38ba8;'>[SYSTEM] Захват остановлен.</b>")

    # -------------------------
    # Packet processing
    # -------------------------
    def process_packet(self, pkt):
        try:
            self.packet_count += 1
            if self.sample_factor > 1 and (self.packet_count % self.sample_factor != 0):
                return

            if pkt is None:
                return

            feat = extract_features(pkt, time.time())
            if feat is None:
                return

            rule_metrics = self.rules.update(feat)

            x = [feat.length, feat.proto, feat.dport]

            # training
            if not self.ml.is_trained:
                n = self.ml.add_train_sample(x)

                if n % 50 == 0:
                    self._log(f"<i>Обучение: {n}/{self.ml.cfg.train_size}...</i>")

                if self.ml.can_train():
                    self.ml.train()
                    self._log("<b style='color:#a6e3a1;'>[SYSTEM] Защита АКТИВИРОВАНА.</b>")
                    self._safe_db("SYSTEM", f"Модель обучена и сохранена (profile={self.profile_name})")
                return

            # inference
            self.total_seen += 1
            is_anom = self.ml.predict_is_anomaly(x)

            if is_anom:
                self.total_anom += 1
                self.attacker_stats[feat.src_ip] += 1
                self._safe_db("ML_ANOMALY", f"{feat.src_ip} -> {feat.dst_ip} dport={feat.dport}")

                if self.attacker_stats[feat.src_ip] % 5 == 0:
                    self._log(f"⚠ АНОМАЛИЯ: {feat.src_ip} -> {feat.dst_ip}")

            # score
            if self.total_seen % 200 == 0:
                anom_rate = self.total_anom / max(1, self.total_seen)

                metrics = {
                    "unique_ports_max": rule_metrics.get("unique_ports_max", 0),
                    "pps": rule_metrics.get("pps", 0.0),
                    "pps_eff": rule_metrics.get("pps_eff", rule_metrics.get("pps", 0.0)),
                    "anom_rate": anom_rate,
                }
                flags = {
                    "scan_rule": bool(rule_metrics.get("scan_rule", False)),
                    "dos_rule": bool(rule_metrics.get("dos_rule", False)),
                }

                ib_score, total_risk, risks, level = calc_ib_score(metrics, flags)
                self.last_ib_score = ib_score
                self.last_ib_level = level

                self._log(
                    f"<span style='color:#f9e2af;'>[ИБ] Score={ib_score}/100 — {level} | "
                    f"scan={risks['Port Scan']:.2f} dos={risks['DoS/Flood']:.2f} ml={risks['ML Anomaly']:.2f}</span>"
                )

                if flags["scan_rule"]:
                    self._safe_db("PORT_SCAN_SUSPECT", f"max_unique_ports={metrics['unique_ports_max']}")
                if flags["dos_rule"]:
                    self._safe_db("DOS_SUSPECT", f"pps={metrics['pps']:.1f}")

        except Exception as e:
            self._log(f"<span style='color:#f38ba8;'>[ENGINE ERROR] {type(e).__name__}: {e}</span>")

    # -------------------------
    # Helpers
    # -------------------------
    def _build_ml(self, profile_name: str, ml_cfg: MLConfig) -> MLDetector:
        pkg_dir = Path(__file__).resolve().parents[1]  # .../NetworkMonitor/NetworkMonitor
        models_dir = pkg_dir / "storage" / "models"
        models_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in profile_name)
        model_path = models_dir / f"model_{safe_name}.joblib"

        return MLDetector(model_path=model_path, cfg=ml_cfg)

    def _safe_db(self, alert_type: str, desc: str):
        try:
            add_alert(alert_type, desc)
        except Exception as e:
            self._log(f"<span style='color:#f38ba8;'>[DB ERROR] {type(e).__name__}: {e}</span>")

    def _log(self, msg: str):
        if self.callback:
            self.callback(msg)