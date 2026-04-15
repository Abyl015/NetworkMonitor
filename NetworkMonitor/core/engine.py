# NetworkMonitor/core/engine.py
from __future__ import annotations

import time
from pathlib import Path
from collections import Counter
from typing import Optional
import scapy.all as scapy
import ipaddress
from NetworkMonitor.core.dedup import AlertDedup
from scapy.layers.tls.handshake import TLSClientHello
from NetworkMonitor.core.features import extract_features
from NetworkMonitor.core.rules import RuleEngine
from NetworkMonitor.core.scoring import calc_security_assessment, format_assessment_line
from NetworkMonitor.core.ml import MLDetector, MLConfig
from NetworkMonitor.storage.database import init_db, add_alert
from datetime import datetime
from NetworkMonitor.core.session import MonitoringSession
scapy.conf.noipaddrs = True


class NetworkEngine:
    def __init__(self, callback):
        self.callback = callback

        # capture control
        self.running: bool = False
        self._sniffer: Optional[scapy.AsyncSniffer] = None

        # profile-related defaults
        self.sample_factor = 5
        self.profile_name = "default"

        # runtime stats
        self.attacker_stats = Counter()
        self.packet_count = 0
        self.total_seen = 0
        self.total_anom = 0
        self.last_ib_score = 100
        self.last_ib_level = "Высокий уровень ИБ"

        self.ioc_file = Path(__file__).resolve().parents[1] / "data" / "iocs" / "malicious_ips.txt"
        self.malicious_ips = self._load_malicious_ips()
        self.domain_ioc_file = Path(__file__).resolve().parents[1] / "data" / "iocs" / "malicious_domains.txt"
        self.malicious_domains = self._load_malicious_domains()
        self.domain_ioc_seen = set()
        self.ioc_seen = set()
        self.infected_host_scores = Counter()
        self.reported_infected_hosts = set()
        self.incidents = {}
        self.alert_dedup = AlertDedup(ttl_sec=300, max_size=10000)
        self.current_session = MonitoringSession()
        self.debug_raw_packets = 0
        self.debug_feat_packets = 0
        self.debug_train_skip_noise = 0
        self.debug_train_skip_ioc = 0
        self.debug_train_added = 0
        # RULES + ML
        self.rules = RuleEngine(sample_factor=self.sample_factor)
        self.ml = self._build_ml(profile_name=self.profile_name, ml_cfg=MLConfig())

    # -------------------------
    # Public controls
    # -------------------------
    def stop_capture(self):
        self.running = False
        try:
            if self._sniffer and self._sniffer.running:
                self._sniffer.stop()
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[STOP ERROR] {type(e).__name__}: {e}</span>"
            )
        finally:
            self._sniffer = None

    def apply_profile(self, profile, profile_name: str = "default"):
        """
        profile может быть dict или Profile(filename, data).
        """
        # поддержка ProfileManager.Profile
        if hasattr(profile, "data"):
            profile_name = getattr(profile, "filename", profile_name) or profile_name
            profile = profile.data

        if not isinstance(profile, dict):
            profile = {}

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

        train_size = ml.get("train_size", ml.get("train_packets", 500))

        ml_cfg = MLConfig(
            contamination=float(ml.get("contamination", 0.005)),
            n_estimators=int(ml.get("n_estimators", 50)),
            train_size=int(train_size),
        )

        # rebuild detector for this profile (auto-loads its own model file)
        self.ml = self._build_ml(profile_name=self.profile_name, ml_cfg=ml_cfg)

        # сброс runtime-статистики при смене профиля
        self._reset_runtime_state()

        # лог статуса модели
        if self.ml.is_trained:
            self._log(
                f"<b style='color:#a6e3a1;'>[PROFILE] ML модель загружена для профиля: "
                f"{self.profile_name}</b>"
            )
        else:
            self._log(
                f"<b style='color:#89dceb;'>[PROFILE] Новый профиль: {self.profile_name}. "
                f"Нужно обучить ML ({self.ml.cfg.train_size} пакетов).</b>"
            )

    def _load_malicious_domains(self) -> set[str]:
        domains = set()

        try:
            if not self.domain_ioc_file.exists():
                return domains

            with self.domain_ioc_file.open("r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip().lower()

                    if not line or line.startswith("#"):
                        continue

                    domains.add(line)
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[IOC ERROR] Не удалось загрузить IOC domain list: "
                f"{type(e).__name__}: {e}</span>"
            )

        return domains

    def _extract_dns_query_name(self, pkt) -> str | None:
        try:
            if not pkt.haslayer(scapy.DNS) or not pkt.haslayer(scapy.DNSQR):
                return None

            dns_layer = pkt[scapy.DNS]

            # только DNS-запросы, не ответы
            if getattr(dns_layer, "qr", 1) != 0:
                return None

            qname = pkt[scapy.DNSQR].qname
            if not qname:
                return None

            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")

            qname = str(qname).strip().rstrip(".").lower()
            return qname or None
        except Exception:
            return None

    def _extract_http_host(self, pkt) -> str | None:
        try:
            if not pkt.haslayer(scapy.Raw):
                return None

            raw_payload = bytes(pkt[scapy.Raw].load)
            if not raw_payload:
                return None

            # HTTP host читаем только из HTTP-запросов
            header_blob = raw_payload[:8192]
            if b"HTTP/" not in header_blob and not any(
                header_blob.startswith(method)
                for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
            ):
                return None

            text = header_blob.decode("utf-8", errors="ignore")

            for line in text.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    if host:
                        return host
            return None
        except Exception:
            return None

    def _extract_tls_sni(self, pkt) -> str | None:
        try:
            if not pkt.haslayer(TLSClientHello):
                return None

            hello = pkt[TLSClientHello]
            ext = getattr(hello, "ext", None) or []

            for item in ext:
                server_names = getattr(item, "servernames", None)
                if not server_names:
                    continue

                for name_obj in server_names:
                    if isinstance(name_obj, bytes):
                        server_name = name_obj
                    else:
                        server_name = getattr(name_obj, "servername", None)
                    if isinstance(server_name, bytes):
                        server_name = server_name.decode("utf-8", errors="ignore")
                    if server_name:
                        return str(server_name).strip()
            return None
        except Exception:
            return None

    def _extract_ioc_domains_from_packet(self, pkt) -> list[tuple[str, str]]:
        domains = []

        dns_domain = self._extract_dns_query_name(pkt)
        if dns_domain:
            domains.append(("dns", dns_domain))

        # HTTP/TLS распознаём только для потенциально релевантного TCP-трафика
        sport = int(getattr(pkt, "sport", 0) or 0)
        dport = int(getattr(pkt, "dport", 0) or 0)
        tcp_ports = {80, 443, 8080, 8443}

        if pkt.haslayer(scapy.TCP) and (sport in tcp_ports or dport in tcp_ports):
            http_domain = self._extract_http_host(pkt)
            if http_domain:
                domains.append(("http", http_domain))

            tls_domain = self._extract_tls_sni(pkt)
            if tls_domain:
                domains.append(("tls", tls_domain))

        return domains

    def _build_ml_vector(self, feat) -> list[float]:
        return [
            float(feat.length),
            float(feat.proto),
            float(feat.dport),
            float(feat.is_tcp),
            float(feat.is_udp),
            float(feat.is_icmp),
            float(feat.is_multicast),
            float(feat.ttl),
            float(feat.tcp_syn),
            float(feat.tcp_ack),
        ]

    def _is_service_discovery_noise(self, feat) -> bool:
        service_ports = {5353, 1900, 3702, 5355, 137, 138}
        if feat.is_multicast:
            return True
        return feat.sport in service_ports or feat.dport in service_ports

    def _check_ioc_domain(self, domain: str) -> str | None:
        if not domain:
            return None

        domain = domain.strip().lower()

        # exact match
        if domain in self.malicious_domains:
            return domain

        # subdomain match
        for bad_domain in self.malicious_domains:
            if domain.endswith("." + bad_domain):
                return bad_domain

        return None

    def _get_possible_local_host(self, src_ip: str, dst_ip: str) -> str:
        if self._is_private_ip(src_ip):
            return src_ip
        if self._is_private_ip(dst_ip):
            return dst_ip
        return src_ip
    # -------------------------
    # Capture
    # -------------------------
    def get_working_iface(self):
        try:
            interfaces = scapy.get_working_ifaces()
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[IFACE ERROR] {type(e).__name__}: {e}</span>"
            )
            return scapy.conf.iface

        best_iface = None

        for iface in interfaces:
            desc = getattr(iface, "description", "") or ""
            iname = getattr(iface, "name", "") or ""
            ip = getattr(iface, "ip", None)

            name = f"{desc} {iname}".lower()

            if not ip or ip == "127.0.0.1":
                continue

            # пропускаем APIPA
            if str(ip).startswith("169.254."):
                continue

            # пропускаем виртуальные / loopback / bluetooth
            bad_words = ["bluetooth", "virtual", "loopback", "npcap", "vmware", "host-only"]
            if any(word in name for word in bad_words):
                continue

            # предпочитаем приватный нормальный IP
            if self._is_private_ip(str(ip)):
                return iface

            if best_iface is None:
                best_iface = iface

        return best_iface or scapy.conf.iface

    def start_capture(self):

        if self.running:
            self._log("<span style='color:#f9e2af;'>[SYSTEM] Захват уже запущен.</span>")
            return

        try:
            init_db()
            self._reset_runtime_state()

            self.malicious_ips = self._load_malicious_ips()
            self.malicious_domains = self._load_malicious_domains()

            self.ioc_seen.clear()
            self.domain_ioc_seen.clear()
            self.infected_host_scores.clear()
            self.reported_infected_hosts.clear()

            self._log(
                f"<b style='color:#89dceb;'>[IOC] Загружено IOC IP: {len(self.malicious_ips)} | "
                f"IOC domains: {len(self.malicious_domains)}</b>"
            )
            scapy.conf.sniff_promisc = True
            scapy.conf.verbose = False


            active_iface = self.get_working_iface()
            iface_desc = (
                getattr(active_iface, "description", None)
                or getattr(active_iface, "name", None)
                or str(active_iface)
            )
            self.current_session = MonitoringSession(
                mode="live",
                profile_name=self.profile_name,
                interface_name=str(iface_desc),
                started_at=datetime.now(),
            )

            self._log(f"<b style='color:#89b4fa;'>[DEBUG] Активен: {iface_desc}</b>")
            self._log(
                f"<b style='color:#89b4fa;'>[DEBUG] IP: {getattr(active_iface, 'ip', 'unknown')}</b>"
            )
            self._log(
                f"<b style='color:#89dceb;'>[SYSTEM] Профиль: {self.profile_name} | "
                f"sampling=1/{self.sample_factor}</b>"
            )

            if self.ml.is_trained:
                self._log("<b style='color:#a6e3a1;'>[SYSTEM] Модель загружена. Защита АКТИВНА.</b>")
            else:
                self._log(
                    f"<b style='color:#89dceb;'>[SYSTEM] Слушаю эфир. "
                    f"(Нужно {self.ml.cfg.train_size} пакетов)</b>"
                )

            self.running = True

            self._sniffer = scapy.AsyncSniffer(
                iface=active_iface,
                prn=self.process_packet,
                store=False,
            )
            self._sniffer.start()
            self._log("<span style='color:#89b4fa;'>[DEBUG] AsyncSniffer started</span>")

            while self.running:
                time.sleep(0.2)

        except PermissionError as e:
            self._log(
                f"<span style='color:#f38ba8;'>[CAPTURE ERROR] Недостаточно прав: {e}</span>"
            )
        except OSError as e:
            self._log(
                f"<span style='color:#f38ba8;'>[CAPTURE ERROR] Ошибка интерфейса/драйвера: {e}</span>"
            )
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>Ошибка захвата: {type(e).__name__}: {e}</span>"
            )
        finally:
            self.current_session.stopped_at = datetime.now()
            self.current_session.total_packets = self.packet_count
            self.current_session.total_anomalies = self.total_anom
            self.current_session.total_ioc_matches = len(self.ioc_seen) + len(self.domain_ioc_seen)
            self.current_session.total_incidents = len(self.incidents)
            self.current_session.final_ib_score = self.last_ib_score
            self.current_session.final_ib_level = self.last_ib_level
            self.stop_capture()
            self._log("<b style='color:#f38ba8;'>[SYSTEM] Захват остановлен.</b>")

    def analyze_pcap(self, pcap_path: str):
        self.current_session = MonitoringSession(
            mode="pcap",
            profile_name=self.profile_name,
            pcap_path=pcap_path,
            started_at=datetime.now(),
        )
        if self.running:
            self._log("<span style='color:#f9e2af;'>[SYSTEM] Сначала остановите текущий захват.</span>")
            return

        try:
            init_db()
            self._reset_runtime_state()

            self.malicious_ips = self._load_malicious_ips()
            self.malicious_domains = self._load_malicious_domains()

            self.ioc_seen.clear()
            self.domain_ioc_seen.clear()
            self.infected_host_scores.clear()
            self.reported_infected_hosts.clear()


            self._log(
                f"<b style='color:#89dceb;'>[IOC] Загружено IOC IP: {len(self.malicious_ips)} | "
                f"IOC domains: {len(self.malicious_domains)}</b>"
            )
            self.running = True

            self._log(f"<b style='color:#89dceb;'>[PCAP] Запуск offline-анализа: {pcap_path}</b>")
            self._log(
                f"<b style='color:#89dceb;'>[SYSTEM] Профиль: {self.profile_name} | "
                f"sampling=1/{self.sample_factor}</b>"
            )

            processed = 0

            with scapy.PcapReader(pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    if not self.running:
                        self._log("<span style='color:#f9e2af;'>[PCAP] Анализ остановлен пользователем.</span>")
                        break

                    self.process_packet(pkt)
                    processed += 1

                    if processed % 200 == 0:
                        self._log(f"<i>[PCAP] Обработано пакетов: {processed}</i>")

            self._log(f"<b style='color:#a6e3a1;'>[PCAP] Анализ завершён. Всего пакетов: {processed}</b>")

        except FileNotFoundError:
            self._log(
                f"<span style='color:#f38ba8;'>[PCAP ERROR] Файл не найден: {pcap_path}</span>"
            )
        except PermissionError as e:
            self._log(
                f"<span style='color:#f38ba8;'>[PCAP ERROR] Нет доступа к файлу: {e}</span>"
            )
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[PCAP ERROR] {type(e).__name__}: {e}</span>"
            )
        finally:
            self.current_session.stopped_at = datetime.now()
            self.current_session.total_packets = self.packet_count
            self.current_session.total_anomalies = self.total_anom
            self.current_session.total_ioc_matches = len(self.ioc_seen) + len(self.domain_ioc_seen)
            self.current_session.total_incidents = len(self.incidents)
            self.current_session.final_ib_score = self.last_ib_score
            self.current_session.final_ib_level = self.last_ib_level
            self.running = False
            self._log("<b style='color:#f38ba8;'>[PCAP] Offline-анализ остановлен.</b>")
    # -------------------------
    # Packet processing
    # -------------------------
    def process_packet(self, pkt):
        try:
            self.packet_count += 1
            self.debug_raw_packets += 1
            if self.debug_raw_packets % 100 == 0:
                self._log(f"<span style='color:#89b4fa;'>[DEBUG] raw packets: {self.debug_raw_packets}</span>")

            if pkt is None:
                return

            packet_ts = float(getattr(pkt, "time", time.time()))
            feat = extract_features(pkt, packet_ts)
            if feat is None:
                return

            self.debug_feat_packets += 1
            if self.debug_feat_packets % 100 == 0:
                self._log(f"<span style='color:#89b4fa;'>[DEBUG] feature packets: {self.debug_feat_packets}</span>")
            # IOC проверяем ВСЕГДА, без sampling
            ioc_ip = self._check_ioc_ip(feat.src_ip, feat.dst_ip)
            if ioc_ip:
                local_ip = feat.src_ip if self._is_private_ip(feat.src_ip) else feat.dst_ip
                event_key = (feat.src_ip, feat.dst_ip, ioc_ip)

                if event_key not in self.ioc_seen:
                    self.ioc_seen.add(event_key)

                    self._log(
                        f"<span style='color:#f38ba8;'>[IOC MATCH] "
                        f"{feat.src_ip} -> {feat.dst_ip} | IOC IP: {ioc_ip} | possible host: {local_ip}</span>"
                    )

                    self._safe_db(
                        "IOC_MATCH",
                        f"{feat.src_ip} -> {feat.dst_ip} | matched_ip={ioc_ip} | possible_host={local_ip}"
                    )
                    self._touch_incident(
                        local_ip,
                        evidence="ioc_ip",
                        remote_ip=ioc_ip,
                    )

                    if self._is_private_ip(local_ip):
                        self.infected_host_scores[local_ip] += 1

                        if (
                                self.infected_host_scores[local_ip] >= 3
                                and local_ip not in self.reported_infected_hosts
                        ):
                            self.reported_infected_hosts.add(local_ip)

                            self._log(
                                f"<b style='color:#f38ba8;'>[INFECTED HOST CANDIDATE] "
                                f"{local_ip} repeatedly communicated with IOC IPs</b>"
                            )

                            self._safe_db(
                                "INFECTED_HOST_CANDIDATE",
                                f"host={local_ip} | ioc_hits={self.infected_host_scores[local_ip]}"
                            )

                            self._touch_incident(
                                local_ip,
                                evidence="infected_host_candidate",
                            )
                # DNS IOC проверяем тоже ВСЕГДА, без sampling
            domain_ioc_hit = False
            for domain_source, domain_value in self._extract_ioc_domains_from_packet(pkt):
                matched_domain = self._check_ioc_domain(domain_value)
                if not matched_domain:
                    continue
                domain_ioc_hit = True

                local_ip = self._get_possible_local_host(feat.src_ip, feat.dst_ip)
                domain_event_key = (feat.src_ip, feat.dst_ip, domain_source, matched_domain)

                if domain_event_key in self.domain_ioc_seen:
                    continue

                self.domain_ioc_seen.add(domain_event_key)

                self._log(
                    f"<span style='color:#f38ba8;'>[IOC DOMAIN MATCH] "
                    f"{feat.src_ip} -> {feat.dst_ip} | source: {domain_source.upper()} | "
                    f"domain: {domain_value} | matched: {matched_domain} | possible host: {local_ip}</span>"
                )

                self._safe_db(
                    "IOC_DOMAIN_MATCH",
                    f"{feat.src_ip} -> {feat.dst_ip} | source={domain_source} | "
                    f"domain={domain_value} | matched_domain={matched_domain} | possible_host={local_ip}"
                )
                self._touch_incident(
                    local_ip,
                    evidence="ioc_domain",
                    remote_ip=feat.dst_ip,
                    domain=matched_domain,
                )

                if self._is_private_ip(local_ip):
                    self.infected_host_scores[local_ip] += 1

                    if (
                            self.infected_host_scores[local_ip] >= 3
                            and local_ip not in self.reported_infected_hosts
                    ):
                        self.reported_infected_hosts.add(local_ip)

                        self._log(
                            f"<b style='color:#f38ba8;'>[INFECTED HOST CANDIDATE] "
                            f"{local_ip} repeatedly communicated with IOC infrastructure</b>"
                        )

                        self._safe_db(
                            "INFECTED_HOST_CANDIDATE",
                            f"host={local_ip} | ioc_hits={self.infected_host_scores[local_ip]}"
                        )
            # sampling только для rules/ML/scoring
            if self.sample_factor > 1 and (self.packet_count % self.sample_factor != 0):
                return
            if self._is_service_discovery_noise(feat):
                rule_metrics = {
                    "pps": 0.0,
                    "pps_eff": 0.0,
                    "unique_ports_src": 0,
                    "unique_ports_max": 0,
                    "scan_rule": False,
                    "dos_rule": False,
                }
            else:
                rule_metrics = self.rules.update(feat)

            local_ip = self._get_possible_local_host(feat.src_ip, feat.dst_ip)

            if bool(rule_metrics.get("scan_rule", False)):
                self._touch_incident(
                    local_ip,
                    evidence="scan_rule",
                    remote_ip=feat.dst_ip,
                )

            if bool(rule_metrics.get("dos_rule", False)):
                self._touch_incident(
                    local_ip,
                    evidence="dos_rule",
                    remote_ip=feat.dst_ip,
                )
            x = self._build_ml_vector(feat)
            ioc_ip_hit = ioc_ip is not None
            ioc_domain_hit = domain_ioc_hit
            event_local_ip = self._get_possible_local_host(feat.src_ip, feat.dst_ip)
            infected_flag = event_local_ip in self.reported_infected_hosts
            scan_rule_flag = bool(rule_metrics.get("scan_rule", False))
            dos_rule_flag = bool(rule_metrics.get("dos_rule", False))

            verdict, reasons = self._classify_event(
                ioc_ip=ioc_ip_hit,
                ioc_domain=ioc_domain_hit,
                scan_rule=scan_rule_flag,
                dos_rule=dos_rule_flag,
                infected_host=infected_flag,
                ml_anomaly=False,
            )
            self._emit_verdict(feat, verdict, reasons)
            # training
            is_noise = self._is_service_discovery_noise(feat)

            if not self.ml.is_trained:
                if is_noise:
                    self.debug_train_skip_noise += 1
                    if self.debug_train_skip_noise % 100 == 0:
                        self._log(
                            f"<span style='color:#f9e2af;'>[TRAIN DEBUG] skipped noise: {self.debug_train_skip_noise}</span>"
                        )
                    return

                if ioc_ip_hit or ioc_domain_hit:
                    self.debug_train_skip_ioc += 1
                    if self.debug_train_skip_ioc % 20 == 0:
                        self._log(
                            f"<span style='color:#f9e2af;'>[TRAIN DEBUG] skipped IOC: {self.debug_train_skip_ioc}</span>"
                        )
                    return

                n = self.ml.add_train_sample(x)
                self.debug_train_added += 1

                if n % 50 == 0:
                    self._log(f"<i>Обучение: {n}/{self.ml.cfg.train_size}.</i>")

                if self.debug_train_added % 50 == 0:
                    self._log(
                        f"<span style='color:#a6e3a1;'>[TRAIN DEBUG] added samples: {self.debug_train_added}</span>"
                    )

                if self.ml.can_train():
                    self.ml.train()
                    self._log("<b style='color:#a6e3a1;'>[SYSTEM] Защита АКТИВИРОВАНА.</b>")
                    self._safe_db(
                        "SYSTEM",
                        f"Модель обучена и сохранена (profile={self.profile_name})",
                    )
                return



            # inference
            if self._is_benign_local_noise(feat) and not ioc_ip_hit and not ioc_domain_hit:
                return
            self.total_seen += 1
            is_anom = self.ml.predict_is_anomaly(x)
            verdict, reasons = self._classify_event(
                ioc_ip=ioc_ip_hit,
                ioc_domain=ioc_domain_hit,
                scan_rule=scan_rule_flag,
                dos_rule=dos_rule_flag,
                infected_host=infected_flag,
                ml_anomaly=is_anom,
            )
            self._emit_verdict(feat, verdict, reasons)
            if is_anom:
                self.total_anom += 1

                local_ip = self._get_possible_local_host(feat.src_ip, feat.dst_ip)
                self.attacker_stats[local_ip] += 1

                self._safe_db(
                    "ML_ANOMALY",
                    f"{feat.src_ip} -> {feat.dst_ip} dport={feat.dport}",
                )

                self._touch_incident(
                    local_ip,
                    evidence="ml_anomaly",
                    remote_ip=feat.dst_ip,
                )

                if self.attacker_stats[local_ip] % 10 == 0:
                    self._log(f"⚠ АНОМАЛИЯ: {feat.src_ip} -> {feat.dst_ip}")
            # score
            if self.total_seen % 200 == 0:
                anom_rate = self.total_anom / max(1, self.total_seen)

                metrics = {
                    "unique_ports_max": rule_metrics.get("unique_ports_max", 0),
                    "pps": rule_metrics.get("pps", 0.0),
                    "pps_eff": rule_metrics.get("pps_eff", rule_metrics.get("pps", 0.0)),
                    "anom_rate": anom_rate,
                    "ioc_matches": len(self.ioc_seen) + len(self.domain_ioc_seen),
                    "infected_hosts": len(self.reported_infected_hosts),
                    "observed_packets": self.total_seen,
                }
                flags = {
                    "scan_rule": bool(rule_metrics.get("scan_rule", False)),
                    "dos_rule": bool(rule_metrics.get("dos_rule", False)),
                    "ioc_match": (len(self.ioc_seen) + len(self.domain_ioc_seen)) > 0,
                    "infected_host_candidate": len(self.reported_infected_hosts) > 0,
                }

                assessment = calc_security_assessment(metrics, flags)

                self.last_ib_score = assessment["overall_score"]
                self.last_ib_level = assessment["security_level"]
                self.last_assessment = assessment
                self.assessment_ready = True

                self._log(
                    f"<span style='color:#f9e2af;'>{format_assessment_line(assessment)}</span>"
                )

                self._log(
                    f"<span style='color:#cdd6f4;'>"
                    f"Сетевой риск={assessment['components']['network_risk']:.2f} | "
                    f"ML риск={assessment['components']['ml_risk']:.2f} | "
                    f"IOC риск={assessment['components']['ioc_risk']:.2f} | "
                    f"Риск компрометации хоста={assessment['components']['host_compromise_risk']:.2f}"
                    f"</span>"
                )

                self._log(
                    f"<span style='color:#bac2de;'>"
                    f"Достоверность={assessment['confidence']} | "
                    f"Вывод: {assessment['summary']}"
                    f"</span>"
                )

                if flags["scan_rule"]:
                    self._safe_db(
                        "PORT_SCAN_SUSPECT",
                        f"max_unique_ports={metrics['unique_ports_max']}",
                    )

                if flags["dos_rule"]:
                    self._safe_db(
                        "DOS_SUSPECT",
                        f"pps={metrics['pps']:.1f}",
                    )

        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[ENGINE ERROR] {type(e).__name__}: {e}</span>"
            )

    def _load_malicious_ips(self) -> set[str]:
        ips = set()

        try:
            if not self.ioc_file.exists():
                return ips

            with self.ioc_file.open("r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()

                    if not line or line.startswith("#"):
                        continue

                    ips.add(line)
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[IOC ERROR] Не удалось загрузить IOC IP list: {type(e).__name__}: {e}</span>"
            )

        return ips

    def _check_ioc_ip(self, src_ip: str, dst_ip: str) -> str | None:
        if src_ip in self.malicious_ips:
            return src_ip
        if dst_ip in self.malicious_ips:
            return dst_ip
        return None

    # -------------------------
    # Helpers
    # -------------------------
    def _is_benign_local_noise(self, feat) -> bool:
        noisy_ports = {137, 138, 1900, 3702, 5353, 5355}
        if feat.dport in noisy_ports or feat.sport in noisy_ports:
            return True
        if feat.is_multicast:
            return True
        if feat.dst_ip == "255.255.255.255":
            return True
        if feat.dst_ip.endswith(".255"):
            return True
        return False

    def _emit_verdict(self, feat, verdict: str, reasons: list[str]):
        if verdict == "normal":
            return

        reason_text = ", ".join(reasons) if reasons else "без уточнения"

        if not self.alert_dedup.should_emit(
                feat.src_ip,
                feat.dst_ip,
                feat.dport,
                verdict,
        ):
            return

        self._log(
            f"<span style='color:#f9e2af;'>[VERDICT] {verdict.upper()} | "
            f"{feat.src_ip} -> {feat.dst_ip} | dport={feat.dport} | reasons: {reason_text}</span>"
        )

        self._safe_db(
            "EVENT_VERDICT",
            f"verdict={verdict} | src={feat.src_ip} | dst={feat.dst_ip} | "
            f"dport={feat.dport} | reasons={reason_text}"
        )

    def _classify_event(
            self,
            *,
            ioc_ip: bool = False,
            ioc_domain: bool = False,
            scan_rule: bool = False,
            dos_rule: bool = False,
            infected_host: bool = False,
            ml_anomaly: bool = False,
    ):
        reasons = []

        if ioc_ip:
            reasons.append("совпадение с IOC IP")
        if ioc_domain:
            reasons.append("совпадение с IOC domain")
        if scan_rule:
            reasons.append("признаки сканирования")
        if dos_rule:
            reasons.append("признаки flood/DoS")
        if ml_anomaly:
            reasons.append("обнаружена ML-anomaly")

        infected_reason = "подозрение на компрометацию внутреннего хоста"

        # 1. IOC = сразу malicious
        if ioc_ip or ioc_domain:
            if infected_host:
                reasons.append(infected_reason)
            return "malicious", reasons

        # 2. Явные rule-hit = suspicious
        if scan_rule or dos_rule:
            if infected_host:
                reasons.append(infected_reason)
            return "suspicious", reasons

        # 3. ML anomaly + infected host = suspicious
        if ml_anomaly and infected_host:
            reasons.append(infected_reason)
            return "suspicious", reasons

        # 4. Только ML anomaly = anomaly
        if ml_anomaly:
            return "anomaly", reasons

        # 5. Только infected_host сам по себе verdict не поднимает
        return "normal", []
    def _is_private_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _new_incident(self, host: str) -> dict:
        return {
            "host": host,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "ioc_ip_hits": 0,
            "ioc_domain_hits": 0,
            "ml_hits": 0,
            "scan_hits": 0,
            "dos_hits": 0,
            "infected_host": False,
            "remote_ips": set(),
            "domains": set(),
            "emitted_verdict": None,
        }

    def _incident_verdict(self, inc: dict) -> str:
        # IOC + любой другой сигнал = malicious
        if (inc["ioc_ip_hits"] > 0 or inc["ioc_domain_hits"] > 0) and (
                inc["ml_hits"] > 0 or inc["scan_hits"] > 0 or inc["dos_hits"] > 0 or inc["infected_host"]
        ):
            return "malicious"

        # IOC сам по себе тоже достаточно сильный сигнал
        if inc["ioc_ip_hits"] > 0 or inc["ioc_domain_hits"] > 0:
            return "malicious"

        # Несколько аномалий или rule-hit = suspicious
        if inc["scan_hits"] > 0 or inc["dos_hits"] > 0 or inc["ml_hits"] >= 3 or inc["infected_host"]:
            return "suspicious"

        return "normal"

    def _emit_incident_if_needed(self, host: str):
        inc = self.incidents.get(host)
        if not inc:
            return

        verdict = self._incident_verdict(inc)
        if verdict == "normal":
            return

        if inc["emitted_verdict"] == verdict:
            return

        inc["emitted_verdict"] = verdict

        summary = (
            f"host={host} | verdict={verdict} | "
            f"ioc_ip={inc['ioc_ip_hits']} | "
            f"ioc_domain={inc['ioc_domain_hits']} | "
            f"ml={inc['ml_hits']} | "
            f"scan={inc['scan_hits']} | "
            f"dos={inc['dos_hits']} | "
            f"remote_ips={len(inc['remote_ips'])} | "
            f"domains={len(inc['domains'])}"
        )

        self._log(
            f"<b style='color:#f38ba8;'>[INCIDENT] {verdict.upper()} | {summary}</b>"
        )

        self._safe_db("INCIDENT", summary)

    def _touch_incident(
            self,
            host: str,
            *,
            evidence: str,
            remote_ip: str | None = None,
            domain: str | None = None,
    ):
        if not host or not self._is_private_ip(host):
            return

        inc = self.incidents.get(host)
        if inc is None:
            inc = self._new_incident(host)
            self.incidents[host] = inc

        inc["last_seen"] = time.time()

        if remote_ip:
            inc["remote_ips"].add(remote_ip)
        if domain:
            inc["domains"].add(domain)

        if evidence == "ioc_ip":
            inc["ioc_ip_hits"] += 1
        elif evidence == "ioc_domain":
            inc["ioc_domain_hits"] += 1
        elif evidence == "ml_anomaly":
            inc["ml_hits"] += 1
        elif evidence == "scan_rule":
            inc["scan_hits"] += 1
        elif evidence == "dos_rule":
            inc["dos_hits"] += 1
        elif evidence == "infected_host_candidate":
            inc["infected_host"] = True

        self._emit_incident_if_needed(host)
    def _build_ml(self, profile_name: str, ml_cfg: MLConfig) -> MLDetector:
        pkg_dir = Path(__file__).resolve().parents[1]
        models_dir = pkg_dir / "storage" / "models"
        models_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "".join(
            ch if ch.isalnum() or ch in ("-", "_") else "_"
            for ch in profile_name
        )
        model_path = models_dir / f"model_{safe_name}.joblib"

        return MLDetector(model_path=model_path, cfg=ml_cfg)

    def _safe_db(self, alert_type: str, desc: str):
        try:
            add_alert(alert_type, desc)
        except Exception as e:
            self._log(
                f"<span style='color:#f38ba8;'>[DB ERROR] {type(e).__name__}: {e}</span>"
            )

    def _reset_runtime_state(self):
        if hasattr(self, "incidents"):
            self.incidents.clear()
        self.alert_dedup.clear()
        self.attacker_stats.clear()
        self.packet_count = 0
        self.total_seen = 0
        self.total_anom = 0

        self.last_ib_score = None
        self.last_ib_level = "Оценка не рассчитана"
        self.last_assessment = None
        self.assessment_ready = False

    def _log(self, msg: str):
        if self.callback:
            self.callback(msg)
        else:
            print(msg)
