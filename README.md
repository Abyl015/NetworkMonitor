# NetworkMonitor / AI Network Guardian v2.0

**AI Network Guardian v2.0** — desktop-приложение на Python для мониторинга сетевого трафика, анализа PCAP-файлов, выявления подозрительной активности и оценки уровня информационной безопасности с помощью **IB Score**.

Проект реализует прототип локальной IDS/monitoring-системы. Приложение анализирует сетевой трафик, применяет rule-based detection, ML-анализ аномалий, проверку IOC, сохраняет результаты в SQLite и формирует HTML-отчёты по сессиям анализа.

---

## Цель проекта

Цель проекта — разработать интеллектуальную систему мониторинга, которая помогает оценивать состояние информационной безопасности локальной сети.

Система предназначена для:

- анализа live network traffic;
- анализа PCAP-файлов;
- выявления suspicious activity;
- обнаружения scan/flood/anomaly-паттернов;
- проверки IP-адресов и доменов по IOC-спискам;
- расчёта итогового **IB Score**;
- хранения истории сессий и алертов;
- формирования HTML-отчётов для анализа и документации.

Проект ориентирован на учебные, исследовательские и демонстрационные сценарии в области кибербезопасности.

---

## Основные возможности

### Мониторинг и анализ трафика

- Захват IP-трафика через **Scapy + Npcap**.
- Анализ live traffic в реальном времени.
- Offline-анализ PCAP-файлов.
- Подсчёт пакетов, аномалий, инцидентов и IOC-срабатываний.
- Отображение live log и событий безопасности в GUI.

### Rule Engine

Rule Engine используется для выявления известных паттернов подозрительной сетевой активности.

Реализованные правила:

- Port Scan detection;
- Flood / DoS detection;
- подозрительная активность по PPS;
- выявление IOC match;
- определение потенциально скомпрометированного внутреннего хоста.

### ML Engine

ML Engine основан на **Isolation Forest**.

Функции ML-модуля:

- unsupervised anomaly detection;
- cold start training;
- обучение на первых `train_size` пакетах;
- сохранение модели по профилю;
- загрузка модели из `storage/models/`;
- использование ML-риск компонента в итоговой оценке.

### IOC Detection

Система поддерживает локальные IOC-списки:

- malicious IP addresses;
- malicious domains.

IOC используются для выявления потенциально вредоносных соединений и доменных запросов.

### IB Score

**IB Score** — интегральная оценка уровня информационной безопасности от `0` до `100`.

Оценка формируется на основе нескольких компонентов:

- network risk;
- ML risk;
- IOC risk;
- host compromise risk;
- total risk;
- итоговый уровень угрозы;
- вероятность инцидента;
- confidence.

Пример интерпретации:

```text
80–100  высокий уровень ИБ
60–79   приемлемый / средний уровень
0–59    повышенный риск
```

---

## Интерфейс приложения

GUI реализован на **PyQt6**.

Основные разделы приложения:

### Мониторинг

Главный Dashboard показывает:

- текущий **IB Score**;
- уровень угрозы;
- вероятность инцидента;
- confidence;
- IOC-срабатывания;
- suspicious hosts;
- последние события безопасности;
- live log;
- топ угроз по IP;
- графики метрик в реальном времени.

### PCAP-анализ

Раздел предназначен для offline-анализа `.pcap` файлов.

Функции:

- открытие PCAP-файла;
- запуск анализа;
- отображение сводки файла;
- отображение оценки безопасности;
- журнал анализа;
- таблица выявленных событий;
- экспорт HTML-отчёта.

### Сессии

Раздел показывает историю мониторинга и анализа.

Возможности:

- список сохранённых сессий;
- поиск по сессиям;
- просмотр оценки безопасности выбранной сессии;
- статистика по сессии;
- сравнение с предыдущей сессией;
- открытие или формирование HTML-отчёта.

### Алерты

Журнал алертов используется для расследования событий безопасности.

Возможности:

- фильтрация по session, period, type, verdict;
- поиск по description;
- таблица алертов;
- детальная информация по выбранному событию;
- linked session assessment;
- оптимизированная загрузка большого количества алертов.

### Настройки

Раздел содержит:

- профили мониторинга;
- параметры Rule Engine;
- параметры ML Engine;
- IOC sources;
- report settings;
- database/storage information.

---

## Архитектура

Общий поток обработки данных:

```text
Scapy / PCAP
    ↓
Feature Extraction
    ↓
Rule Engine + ML Detector
    ↓
Scoring Module / IB Score
    ↓
SQLite / GUI / HTML Report
```

### Ключевые модули

```text
NetworkMonitor/app/main.py
```

Главное PyQt6-приложение, GUI, навигация, Dashboard, PCAP, Sessions, Alerts, Settings.

```text
NetworkMonitor/app/worker.py
```

Фоновый worker для захвата и анализа трафика.

```text
NetworkMonitor/app/plot_widget.py
```

Виджет графиков на matplotlib.

```text
NetworkMonitor/core/engine.py
```

Основной движок обработки трафика, правил, ML и логирования.

```text
NetworkMonitor/core/rules.py
```

Rule Engine: scan, flood/DoS, PPS-based detection.

```text
NetworkMonitor/core/ml.py
```

Isolation Forest, обучение и загрузка ML-моделей.

```text
NetworkMonitor/core/scoring.py
```

Расчёт IB Score, total risk и компонентов риска.

```text
NetworkMonitor/core/report_builder.py
```

Генерация HTML-отчётов по сессиям и текущему анализу.

```text
NetworkMonitor/storage/database.py
```

SQLite-хранилище: alerts, monitoring_sessions, session assessment, history.

```text
NetworkMonitor/config/profile_manager.py
```

Управление профилями мониторинга.

```text
NetworkMonitor/reports/export.py
```

Legacy CSV/summary export для выгрузки alerts.

---

## Хранение данных

Система использует локальную SQLite-базу данных.

Основные сущности:

- `alerts`;
- `monitoring_sessions`;
- session assessment fields;
- linked alerts;
- risk components;
- findings;
- report path.

Локальная runtime-база не должна храниться в GitHub.

Пример игнорируемых файлов:

```gitignore
*.db
*.sqlite
*.sqlite3
NetworkMonitor/storage/traffic_data.db
```

---

## HTML-отчёты

Система формирует HTML-отчёт по сессии мониторинга или PCAP-анализу.

Отчёт включает:

- общую информацию о сессии;
- режим анализа;
- источник трафика;
- профиль мониторинга;
- итоговый IB Score;
- уровень угрозы;
- вероятность инцидента;
- confidence;
- total risk;
- состав оценки;
- ключевые выводы;
- статистику;
- связанные алерты;
- топ типов алертов;
- топ подозрительных значений;
- рекомендации;
- сравнение с предыдущей сессией.

HTML-отчёт оформлен в светлом enterprise/SOC-стиле и может использоваться как артефакт для документации или защиты проекта.

---

## Установка

### Требования

- Windows 10/11;
- Python 3.x;
- Npcap;
- Git;
- virtual environment.

Для live traffic monitoring на Windows требуется установленный **Npcap**.

### Клонирование проекта

```powershell
git clone https://github.com/Abyl015/NetworkMonitor.git
cd NetworkMonitor
```

### Создание виртуального окружения

```powershell
py -m venv .venv
.\.venv\Scripts\activate
```

### Установка зависимостей

```powershell
pip install -U pip
pip install -r requirements.txt
```

---

## Запуск

Из корня проекта:

```powershell
python NetworkMonitor\app\main.py
```

Если используется другой Python launcher:

```powershell
py NetworkMonitor\app\main.py
```

---

## Использование

### Live monitoring

1. Запустить приложение.
2. Открыть вкладку `Мониторинг`.
3. Выбрать сетевой интерфейс.
4. Нажать `Старт`.
5. Наблюдать за live log, events, IB Score и метриками.
6. Нажать `Стоп` для завершения сессии.
7. Сформировать HTML-отчёт при необходимости.

### PCAP-анализ

1. Открыть вкладку `PCAP-анализ`.
2. Нажать `Открыть PCAP`.
3. Выбрать `.pcap` файл.
4. Нажать `Анализ`.
5. Дождаться завершения обработки.
6. Просмотреть оценку, лог и события.
7. Нажать `Экспорт отчёта`.

### Работа с алертами

1. Открыть вкладку `Алерты`.
2. Использовать фильтры по сессии, периоду, типу и verdict.
3. Выбрать алерт в таблице.
4. Посмотреть детали события.
5. Проверить связанную оценку сессии.

### Работа с сессиями

1. Открыть вкладку `Сессии`.
2. Выбрать сохранённую сессию.
3. Просмотреть IB Score, explanation, statistics и comparison.
4. Нажать `Отчёт` для открытия или формирования HTML-отчёта.

---

## Roadmap

### v1.0 — Базовый прототип IDS

- [x] Захват и базовый анализ сетевого трафика
- [x] Rule-based detection для scan/flood-паттернов
- [x] ML anomaly detection на Isolation Forest
- [x] Базовый IB Score
- [x] SQLite-журнал alerts
- [x] Базовый PyQt6 GUI

### v1.1 — Стабильность и PCAP-анализ

- [x] Реализовать единый путь к SQLite
- [x] Улучшить обработку ошибок Scapy/Npcap
- [x] Добавить режим offline-анализа PCAP-файлов
- [x] Добавить сохранение ML-моделей по профилям

### v1.2 — IOC и интерпретация угроз

- [x] Добавить проверку IP-адресов по локальной IOC-базе
- [x] Добавить проверку DNS-доменов по IOC-спискам
- [x] Выявлять предполагаемый заражённый внутренний хост
- [x] Добавить explainability для сработавших правил и причин снижения IB Score
- [x] Выводить verdict: anomaly / suspicious / malicious

### v1.3 — GUI, Sessions, Alerts и отчётность

- [x] Добавить Dashboard с IB Score
- [x] Добавить PCAP Analysis screen
- [x] Добавить Sessions history
- [x] Добавить Alerts journal с фильтрами
- [x] Добавить linked session assessment
- [x] Добавить HTML-отчёты по сессиям
- [x] Улучшить sidebar navigation с SVG-иконками
- [x] Русифицировать интерфейс с сохранением технических терминов
- [x] Оптимизировать загрузку большого количества alerts

### v2.0 — Текущая версия

- [x] Live traffic monitoring через Scapy + Npcap
- [x] Offline PCAP analysis
- [x] Rule Engine для scan/flood/anomaly-паттернов
- [x] ML Engine на Isolation Forest
- [x] IOC-проверка IP-адресов
- [x] IOC-проверка DNS-доменов
- [x] Выявление потенциально скомпрометированного хоста
- [x] Расчёт IB Score
- [x] SQLite-хранилище alerts и monitoring sessions
- [x] Dashboard с оценкой безопасности
- [x] PCAP Analysis screen
- [x] Sessions history
- [x] Alerts journal with filters
- [x] Linked session assessment
- [x] HTML security assessment report
- [x] Sidebar navigation with SVG icons
- [x] Русификация интерфейса с сохранением технических терминов

### v2.1 — Стабильность и производительность

- [x] Оптимизировать загрузку большого количества alerts
- [x] Добавить batching части UI-обновлений во время PCAP-анализа
- [x] Улучшить throttling логов и графиков при больших объёмах данных
- [x] Разделить Dashboard live monitoring и PCAP offline analysis
- [x] Добавить кроссплатформенные runtime paths для Windows/macOS/Linux
- [ ] Оптимизировать обработку крупных PCAP-файлов
- [ ] Добавить progress bar для PCAP-анализа
- [ ] Вынести тяжёлые вычисления в отдельный процесс
- [ ] Добавить более подробные empty-state сообщения

### v2.2 — Улучшение detection logic

- [x] Усилить локальную IOC-обработку: комментарии, нормализация, безопасный subdomain matching
- [x] Добавить AbuseIPDB enrichment для публичных IP-адресов
- [x] Добавить API Keys / Threat Intelligence настройки
- [x] Добавить защиту от отправки private/internal IP во внешние API
- [x] Использовать существующие DNS/HTTP/TLS доменные кандидаты для IOC matching
- [ ] Расширить IOC enrichment для публичных IP
- [ ] Добавить ASN, geolocation и reputation context
- [ ] Улучшить корреляцию событий в инциденты
- [ ] Выполнить калибровку IB Score для разных типов сетей
- [ ] Добавить расширенную explainability по каждому risk component

### v2.3 — Отчётность и аналитика

- [x] HTML-отчёт по сессии
- [x] PDF-экспорт отчёта
- [x] Выбор формата отчёта: HTML / PDF
- [x] Risk breakdown в отчёте
- [x] Recommendations в отчёте
- [x] Сравнение с предыдущей сессией
- [x] Analyst Assessment в отчёте
- [x] Privacy Note в отчёте
- [x] Detection Limitations в отчёте
- [x] Раздел “Аналитика” за период
- [x] Средний, минимальный и максимальный IB Score за период
- [x] Графики динамики IB Score и событий за период
- [x] Triage-контекст в Alerts
- [ ] Добавить топ IP-адресов в HTML/PDF-отчёт
- [ ] Добавить графики в HTML/PDF-отчёт
- [ ] Добавить расширенный incident timeline

### v3.0 — Возможное развитие в web/SOC platform

- [ ] Выделить backend на FastAPI
- [ ] Создать web dashboard
- [ ] Добавить PostgreSQL support
- [ ] Реализовать multi-user mode
- [ ] Добавить интеграции с SIEM/Wazuh/Splunk
- [ ] Добавить REST API для внешних систем
- [ ] Реализовать agent-based architecture для удалённых хостов

---

## Ограничения текущей версии

Текущая версия является desktop-прототипом локальной системы мониторинга.

Известные ограничения:

- анализ крупных PCAP-файлов может создавать повышенную нагрузку на интерфейс;
- точность IB Score зависит от выбранного профиля, IOC-списков и калибровки порогов;
- ML-модель требует достаточного объёма нормального трафика для более стабильного baseline;
- проект ориентирован на detection/assessment, а не на автоматическую блокировку атак;
- IPS-режим и активное реагирование пока не реализованы.

Эти ограничения вынесены в Roadmap и рассматриваются как направления дальнейшего развития.

---

## Статус проекта

Проект находится в стадии рабочего прототипа.

Текущая версия включает основные компоненты:

- traffic capture;
- PCAP analysis;
- Rule Engine;
- ML anomaly detection;
- IOC detection;
- IB Score;
- SQLite history;
- Dashboard;
- Sessions;
- Alerts;
- Settings;
- HTML reports.

Проект может использоваться для демонстрации подхода к интеллектуальному мониторингу сетевой безопасности и оценки уровня ИБ.

---

