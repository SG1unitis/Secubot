import sqlite3
import os
from datetime import datetime, timedelta
from modules.intelligence import defang_url

# Configuration du chemin de la base de données
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "secubot_history.db")

def init_db():
    """Initialise ou migre la base de données SQLite."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                url_defanged TEXT NOT NULL,
                domain TEXT,
                verdict TEXT NOT NULL,
                ssl_recent INTEGER DEFAULT 0
            )
        """)

        cursor = conn.execute("PRAGMA table_info(analysis_history)")
        colonnes = [row[1] for row in cursor.fetchall()]

        if "ssl_recent" not in colonnes:
            conn.execute(
                "ALTER TABLE analysis_history ADD COLUMN ssl_recent INTEGER DEFAULT 0"
            )

def log_analysis(url, domain, verdict, is_recent_ssl=False):
    """Enregistre une nouvelle analyse avec URL neutralisée (defanged)."""
    safe_url = defang_url(url)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO analysis_history (timestamp, url_defanged, domain, verdict, ssl_recent) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(), safe_url, domain, verdict, int(is_recent_ssl))
            )
    except Exception as e:
        print(f"[!] Erreur SQLite (Log) : {e}")

def get_cached_verdict(url, max_age_hours=24):
    """
    Vérifie si une analyse récente existe en base.
    Retourne le verdict (str) ou None.
    """
    safe_url = defang_url(url)
    limit = datetime.now() - timedelta(hours=max_age_hours)
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT verdict FROM analysis_history WHERE url_defanged = ? AND timestamp >= ? ORDER BY timestamp DESC LIMIT 1",
                (safe_url, limit)
            )
            row = cursor.fetchone()
            return row[0] if row else None
    except Exception as e:
        print(f"[!] Erreur SQLite (Cache) : {e}")
        return None