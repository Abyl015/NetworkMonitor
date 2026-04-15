from datetime import datetime


def format_duration(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def build_html_report(session, engine) -> str:
    started = session.started_at.strftime("%Y-%m-%d %H:%M:%S") if session.started_at else "-"
    stopped = session.stopped_at.strftime("%Y-%m-%d %H:%M:%S") if session.stopped_at else "-"
    duration = format_duration(session.duration_seconds())

    incidents_rows = []
    for host, inc in engine.incidents.items():
        incidents_rows.append(f"""
        <tr>
            <td>{host}</td>
            <td>{inc.get("ioc_ip_hits", 0)}</td>
            <td>{inc.get("ioc_domain_hits", 0)}</td>
            <td>{inc.get("ml_hits", 0)}</td>
            <td>{inc.get("scan_hits", 0)}</td>
            <td>{inc.get("dos_hits", 0)}</td>
            <td>{"Да" if inc.get("infected_host") else "Нет"}</td>
        </tr>
        """)

    if not incidents_rows:
        incidents_rows.append("""
        <tr>
            <td colspan="7">Инциденты не обнаружены</td>
        </tr>
        """)

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>NetworkMonitor Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 32px;
                color: #222;
            }}
            h1, h2 {{
                color: #111;
            }}
            .meta {{
                margin-bottom: 20px;
                padding: 12px;
                border: 1px solid #ccc;
                background: #f7f7f7;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
                font-size: 14px;
            }}
            th {{
                background: #eaeaea;
            }}
            .summary {{
                margin-top: 20px;
                padding: 12px;
                border-left: 4px solid #444;
                background: #fafafa;
            }}
        </style>
    </head>
    <body>
        <h1>Отчёт NetworkMonitor</h1>

        <div class="meta">
            <p><b>Дата формирования:</b> {generated}</p>
            <p><b>Режим:</b> {session.mode}</p>
            <p><b>Профиль:</b> {session.profile_name}</p>
            <p><b>Интерфейс:</b> {session.interface_name or "-"}</p>
            <p><b>PCAP:</b> {session.pcap_path or "-"}</p>
            <p><b>Время запуска:</b> {started}</p>
            <p><b>Время остановки:</b> {stopped}</p>
            <p><b>Длительность:</b> {duration}</p>
        </div>

        <h2>Сводка</h2>
        <table>
            <tr><th>Показатель</th><th>Значение</th></tr>
            <tr><td>Обработано пакетов</td><td>{session.total_packets}</td></tr>
            <tr><td>ML аномалий</td><td>{session.total_anomalies}</td></tr>
            <tr><td>IOC совпадений</td><td>{session.total_ioc_matches}</td></tr>
            <tr><td>Инцидентов</td><td>{session.total_incidents}</td></tr>
            <tr><td>Итоговый IB Score</td><td>{session.final_ib_score if session.final_ib_score is not None else "-"}</td></tr>
            <tr><td>Итоговый уровень ИБ</td><td>{session.final_ib_level}</td></tr>
        </table>

        <div class="summary">
            <p><b>Вывод:</b> 
            По результатам мониторинга система обработала {session.total_packets} пакетов.
            Обнаружено ML аномалий: {session.total_anomalies}, IOC совпадений: {session.total_ioc_matches},
            инцидентов: {session.total_incidents}. Итоговый уровень ИБ: {session.final_ib_level}.
            </p>
        </div>

        <h2>Инциденты</h2>
        <table>
            <tr>
                <th>Host</th>
                <th>IOC IP</th>
                <th>IOC Domain</th>
                <th>ML Hits</th>
                <th>Scan Hits</th>
                <th>DoS Hits</th>
                <th>Compromised</th>
            </tr>
            {''.join(incidents_rows)}
        </table>
    </body>
    </html>
    """