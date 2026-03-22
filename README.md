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

## Установка

### 1) Требования
- Windows 10/11
- Python 3.x
- **Npcap** (обязательно для sniff на Windows)

### 2) Установка проекта
```powershell
git clone https://github.com/<your-username>/NetworkMonitor.git
cd NetworkMonitor
py -m venv .venv
.\.venv\Scripts\activate
pip install -U pip
