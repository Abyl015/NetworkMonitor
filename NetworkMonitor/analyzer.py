import scapy.all as scapy
from sklearn.ensemble import IsolationForest
from collections import Counter

# Отключаем DNS-запросы сразу
scapy.conf.noipaddrs = True


class NetworkEngine:
    def __init__(self, callback):
        self.callback = callback
        self.model = IsolationForest(contamination=0.005, n_estimators=50)
        self.is_trained = False
        self.train_buffer = []
        self.attacker_stats = Counter()
        self.packet_count = 0

    def get_working_iface(self):
        """Ищет реальный интерфейс Wi-Fi или Ethernet"""
        interfaces = scapy.get_working_ifaces()
        # Ищем адаптер, который не Bluetooth и не Loopback, и имеет IP
        for iface in interfaces:
            # На некоторых платформах description может быть None.
            # Тогда используем имя интерфейса, чтобы не падать на .lower().
            description = getattr(iface, 'description', '') or ''
            iface_name = getattr(iface, 'name', '') or ''
            name = f"{description} {iface_name}".lower()
            if iface.ip and iface.ip != '127.0.0.1':
                # Игнорируем Bluetooth и виртуальные адаптеры
                if "bluetooth" not in name and "virtual" not in name:
                    return iface
        return scapy.conf.iface  # Если ничего не нашли, берем стандартный

    def start_capture(self):
        scapy.conf.sniff_promisc = True
        scapy.conf.verbose = False

        # 2. Поиск интерфейса
        active_iface = self.get_working_iface()

        # Выводим подробности об адаптере
        iface_desc = getattr(active_iface, 'description', str(active_iface))
        self.callback(f"<b style='color: #89b4fa;'>[DEBUG] Активен: {iface_desc}</b>")
        self.callback(f"<b style='color: #89b4fa;'>[DEBUG] IP: {getattr(active_iface, 'ip', 'unknown')}</b>")

        self.callback("<b style='color: #89dceb;'>[SYSTEM] Слушаю эфир... (Нужно 500 пакетов)</b>")

        try:
            # Запускаем сниффер на конкретном интерфейсе
            scapy.sniff(
                iface=active_iface,
                prn=self.process_packet,
                store=0,
                filter="ip"
            )
        except Exception as e:
            self.callback(f"<span style='color: #f38ba8;'>Ошибка захвата: {e}</span>")

    def process_packet(self, pkt):
        # Пропуск пакетов для стабильности (каждый 20-й)
        self.packet_count += 1
        if self.packet_count % 20 != 0:
            return

        if pkt.haslayer('IP'):
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst

            try:
                dport = pkt.dport if hasattr(pkt, 'dport') else 0
                features = [len(pkt), int(pkt.proto), dport]
            except:
                return

            if not self.is_trained:
                self.train_buffer.append(features)
                # Выводим прогресс каждые 50 пакетов
                if len(self.train_buffer) % 50 == 0:
                    self.callback(f"<i>Обучение: {len(self.train_buffer)}/500...</i>")

                if len(self.train_buffer) >= 500:
                    self.model.fit(self.train_buffer)
                    self.is_trained = True
                    self.callback("<b style='color: #a6e3a1;'>[SYSTEM] Защита АКТИВИРОВАНА.</b>")
            else:
                prediction = self.model.predict([features])
                if prediction[0] == -1:
                    self.attacker_stats[src_ip] += 1
                    if self.attacker_stats[src_ip] % 5 == 0:
                        self.callback(f"⚠ АНОМАЛИЯ: {src_ip} -> {dst_ip}")
