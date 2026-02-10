import sqlite3

def init_db():
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_alert(alert_type, description):
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO alerts (alert_type, description) VALUES (?, ?)',
                   (alert_type, description))
    conn.commit()
    conn.close()