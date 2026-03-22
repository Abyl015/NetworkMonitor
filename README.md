# NetworkMonitor (AI Network Guardian v2.0)

Интеллектуальная система мониторинга сетевого трафика для **оценки уровня информационной безопасности (ИБ)**.  
Проект реализует прототип **IDS**: анализирует трафик в реальном времени, выявляет подозрительную активность (scan/flood/anomaly) и рассчитывает **IB Score (0–100)**.

---

## Возможности

- **Захват IP-трафика** на Windows через **Scapy + Npcap**
- **Rule Engine**:
  - Port Scan (по количеству уникальных портов)
  - Flood/DoS (по PPS в окне времени, с учетом sampling)
- **ML Engine (Isolation Forest)**:
  - Unsupervised anomaly detection
  - Cold start (обучение на первых `train_size` пакетах)
  - **Сохранение модели по профилю** (`storage/models/model_<profile>.joblib`)
- **IB Score (0–100)** + уровень ИБ (Высокий/Средний/Низкий)
- **GUI на PyQt6**:
  - живой лог
  - топ угроз по IP
  - графики `PPS_eff` и `anom_rate`
  - окно профилей/настроек
- **SQLite журнал событий** (`alerts`)
- **Экспорт отчета**: CSV + summary

---

## Архитектура (кратко)

**Поток данных:**

Capture (Scapy) → Feature Extraction → Rule Engine + ML Detector → Scoring (IB Score) → SQLite/GUI/Export

**Ключевые модули:**
- `NetworkMonitor/core/engine.py` — захват, обработка, правила+ML, скоринг, логирование
- `NetworkMonitor/core/rules.py` — правила scan/DoS + метрики `pps_eff`
- `NetworkMonitor/core/ml.py` — Isolation Forest (save/load per profile)
- `NetworkMonitor/core/scoring.py` — расчет IB Score и рисков
- `NetworkMonitor/storage/database.py` — SQLite `alerts`
- `NetworkMonitor/app/main.py` — GUI + графики
- `NetworkMonitor/app/settings_dialog.py` — управление профилями
- `NetworkMonitor/app/plot_widget.py` — matplotlib графики (dark theme)
- `NetworkMonitor/reports/export.py` — экспорт CSV/summary
- `NetworkMonitor/config/profiles/*.json` — профили (настройки)

---
## Roadmap

### Уже реализовано
- [x] Захват и базовый анализ сетевого трафика
- [x] Сохранение данных и событий в SQLite
- [x] Базовый rule-based анализ сетевой активности
- [x] Использование ML-подхода для выявления аномалий
- [x] Базовый графический интерфейс приложения
- [x] Формирование базовых отчётов по результатам анализа

### v1.1 — Повышение стабильности и качества данных
- [x] Реализовать единый путь к SQLite, чтобы исключить создание нескольких БД при разных способах запуска
- [x] Улучшить обработку ошибок при захвате трафика и работе Scapy
- [ ] Добавить режим анализа PCAP-файлов без реального захвата трафика

### v1.2 — Улучшение оценки уровня информационной безопасности
- [ ] Выполнить калибровку порогов и нормализации метрик для разных типов сетей
- [ ] Реализовать механизм explainability для пояснения причин снижения IB Score
- [ ] Добавить базовую корреляцию событий с объединением связанных событий в инциденты

### v1.3 — Развитие интерфейса и отчётности
- [ ] Добавить вкладки в GUI: Журнал, Алерты, Отчёты, Настройки
- [ ] Реализовать просмотр истории алертов из SQLite с возможностью фильтрации
- [ ] Улучшить экспорт отчётов: добавить сведения об инцидентах, параметрах профиля, топ IP-адресах и итоговом уровне оценки

### v1.4 — Расширение функциональности
- [ ] Добавить опциональный IPS-режим с возможностью блокировки IP-адресов
- [ ] Реализовать OSINT enrichment для публичных IP-адресов: геолокация, ASN и репутационные данные
## Установка

### 1) Требования
- Windows 10/11
- Python 3.x
- **Npcap** (обязательно для sniff на Windows)

### 2) Установка проекта
```powershell
git clone https://github.com/Abyl015/NetworkMonitor.git
cd NetworkMonitor
py -m venv .venv
.\.venv\Scripts\activate
pip install -U pip
