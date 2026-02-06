import sqlite3
from datetime import datetime
from typing import Optional

from src.config import DB_PATH
from src.logger import get_logger
from src.parser import AccessEntry, SystemLogEntry

logger = get_logger(__name__)


class LogDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                size INTEGER NOT NULL,
                referer TEXT,
                user_agent TEXT
            );

            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                hostname TEXT,
                pid INTEGER
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                description TEXT NOT NULL,
                value REAL NOT NULL,
                z_score REAL NOT NULL,
                detected_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_access_timestamp ON access_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_access_ip ON access_logs(ip);
            CREATE INDEX IF NOT EXISTS idx_access_status ON access_logs(status);
            CREATE INDEX IF NOT EXISTS idx_system_timestamp ON system_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_system_level ON system_logs(level);
            CREATE INDEX IF NOT EXISTS idx_system_source ON system_logs(source);
            """
        )
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")

    def insert_entries(self, entries: list[AccessEntry]):
        conn = self._get_conn()
        data = [
            (
                e.ip,
                e.timestamp.isoformat(),
                e.method,
                e.path,
                e.status,
                e.size,
                e.referer,
                e.user_agent,
            )
            for e in entries
        ]
        conn.executemany(
            "INSERT INTO access_logs (ip, timestamp, method, path, status, size, referer, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            data,
        )
        conn.commit()
        conn.close()
        logger.info(f"Inserted {len(entries)} access entries")

    def insert_system_entries(self, entries: list[SystemLogEntry]):
        conn = self._get_conn()
        data = [
            (
                e.timestamp.isoformat(),
                e.level,
                e.source,
                e.message,
                e.hostname,
                e.pid,
            )
            for e in entries
        ]
        conn.executemany(
            "INSERT INTO system_logs (timestamp, level, source, message, hostname, pid) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            data,
        )
        conn.commit()
        conn.close()
        logger.info(f"Inserted {len(entries)} system log entries")

    def insert_anomaly(self, type_: str, description: str, value: float, z_score: float):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO anomalies (type, description, value, z_score, detected_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (type_, description, value, z_score, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

    def get_summary(self) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as total, "
            "COUNT(DISTINCT ip) as unique_ips, "
            "MIN(timestamp) as first_entry, "
            "MAX(timestamp) as last_entry, "
            "SUM(size) as total_bytes "
            "FROM access_logs"
        ).fetchone()
        conn.close()
        return dict(row)

    def get_system_summary(self) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as total, "
            "COUNT(DISTINCT source) as unique_sources, "
            "COUNT(DISTINCT hostname) as unique_hosts, "
            "MIN(timestamp) as first_entry, "
            "MAX(timestamp) as last_entry "
            "FROM system_logs"
        ).fetchone()
        conn.close()
        return dict(row)

    def get_top_ips(self, limit: int = 10) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT ip, COUNT(*) as count FROM access_logs "
            "GROUP BY ip ORDER BY count DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_top_paths(self, limit: int = 10) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT path, COUNT(*) as count FROM access_logs "
            "GROUP BY path ORDER BY count DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_status_distribution(self) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM access_logs "
            "GROUP BY status ORDER BY status"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_level_distribution(self) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT level, COUNT(*) as count FROM system_logs "
            "GROUP BY level ORDER BY count DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_top_sources(self, limit: int = 10) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT source, COUNT(*) as count FROM system_logs "
            "GROUP BY source ORDER BY count DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_entries(
        self,
        start: Optional[str] = None,
        end: Optional[str] = None,
        status: Optional[int] = None,
        limit: int = 10000,
    ) -> list[dict]:
        conn = self._get_conn()
        query = "SELECT * FROM access_logs WHERE 1=1"
        params = []

        if start:
            query += " AND timestamp >= ?"
            params.append(start)
        if end:
            query += " AND timestamp <= ?"
            params.append(end)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY timestamp LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_system_entries(
        self,
        start: Optional[str] = None,
        end: Optional[str] = None,
        level: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 10000,
    ) -> list[dict]:
        conn = self._get_conn()
        query = "SELECT * FROM system_logs WHERE 1=1"
        params = []

        if start:
            query += " AND timestamp >= ?"
            params.append(start)
        if end:
            query += " AND timestamp <= ?"
            params.append(end)
        if level:
            query += " AND level = ?"
            params.append(level)
        if source:
            query += " AND source = ?"
            params.append(source)

        query += " ORDER BY timestamp LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_anomalies(self, limit: int = 50) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM anomalies ORDER BY detected_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_entry_count(self) -> int:
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        conn.close()
        return count

    def get_system_entry_count(self) -> int:
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM system_logs").fetchone()[0]
        conn.close()
        return count

    def reset(self):
        conn = self._get_conn()
        conn.executescript(
            "DELETE FROM access_logs; DELETE FROM system_logs; DELETE FROM anomalies;"
        )
        conn.commit()
        conn.close()
        logger.info("Database reset")
