import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTextEdit, QVBoxLayout,
                             QHBoxLayout, QWidget, QPushButton, QLabel, QListWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from analyzer import NetworkEngine


# 1. Поток для работы Scapy
class CaptureThread(QThread):
    message_received = pyqtSignal(str)

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.engine.callback = self.message_received.emit

    def run(self):
        try:
            self.engine.start_capture()
        except Exception as e:
            self.message_received.emit(f"Ошибка потока: {e}")


# 2. Главное окно
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Network Guardian v2.0")
        self.resize(1100, 650)
        self.is_monitoring = False

        # --- Интерфейс ---
        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        self.action_btn = QPushButton("ЗАПУСТИТЬ МОНИТОРИНГ")
        self.action_btn.clicked.connect(self.toggle_monitoring)

        left_layout.addWidget(QLabel("🛡️ Живой лог трафика"))
        left_layout.addWidget(self.log_area)
        left_layout.addWidget(self.action_btn)

        right_layout = QVBoxLayout()
        self.stats_list = QListWidget()
        right_layout.addWidget(QLabel("⚠️ Топ угроз по IP"))
        right_layout.addWidget(self.stats_list)
        right_layout.setContentsMargins(10, 0, 10, 0)

        main_layout.addLayout(left_layout, stretch=3)
        main_layout.addLayout(right_layout, stretch=1)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # Движок
        self.engine = NetworkEngine(None)
        self.capture_thread = CaptureThread(self.engine)
        self.capture_thread.message_received.connect(self.update_log)

    def update_log(self, message):
        self.log_area.append(message)
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())
        self.update_stats_display()

    def update_stats_display(self):
        self.stats_list.clear()
        top_attackers = self.engine.attacker_stats.most_common(10)
        for ip, count in top_attackers:
            self.stats_list.addItem(f" {ip} → {count} атак")

    def toggle_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.action_btn.setText("ОСТАНОВИТЬ МОНИТОРИНГ")
            self.action_btn.setObjectName("stop_mode")
            self.action_btn.setStyle(self.action_btn.style())
            self.log_area.append("<b style='color: #a6e3a1;'>[SYSTEM] Мониторинг запущен...</b>")
            self.capture_thread.start()
        else:
            self.log_area.append("<b style='color: #f38ba8;'>[SYSTEM] Перезапустите программу для сброса.</b>")
            self.action_btn.setEnabled(False)


# 3. ЗАПУСК (Этот блок должен быть СТРОГО без отступов слева)
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Загрузка стилей
    try:
        with open("styles.qss", "r") as f:
            app.setStyleSheet(f.read())
    except:
        pass

    window = MainWindow()
    window.show()
    sys.exit(app.exec())