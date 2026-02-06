import numpy as np
import pandas as pd

from src.config import ANOMALY_THRESHOLD
from src.database import LogDatabase
from src.logger import get_logger

logger = get_logger(__name__)


class AnomalyDetector:
    def __init__(self, db: LogDatabase, threshold: float = ANOMALY_THRESHOLD):
        self.db = db
        self.threshold = threshold

    def _load_df(self) -> pd.DataFrame:
        entries = self.db.get_entries()
        if not entries:
            return pd.DataFrame()
        df = pd.DataFrame(entries)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def _z_scores(self, series: pd.Series) -> pd.Series:
        mean = series.mean()
        std = series.std()
        if std == 0:
            return pd.Series(0, index=series.index)
        return (series - mean) / std

    def detect_traffic_spikes(self, interval: str = "1h") -> list[dict]:
        df = self._load_df()
        if df.empty:
            return []

        traffic = df.set_index("timestamp").resample(interval).size()
        z = self._z_scores(traffic)

        anomalies = []
        for ts, z_val in z.items():
            if abs(z_val) > self.threshold:
                anomalies.append(
                    {
                        "type": "traffic_spike",
                        "timestamp": str(ts),
                        "value": int(traffic[ts]),
                        "z_score": round(float(z_val), 2),
                        "description": f"Traffic spike: {int(traffic[ts])} requests (z={z_val:.2f})",
                    }
                )

        logger.info(f"Detected {len(anomalies)} traffic anomalies")
        return anomalies

    def detect_error_spikes(self, interval: str = "1h") -> list[dict]:
        df = self._load_df()
        if df.empty:
            return []

        df["is_error"] = df["status"] >= 400
        error_counts = df.set_index("timestamp").resample(interval)["is_error"].sum()
        z = self._z_scores(error_counts)

        anomalies = []
        for ts, z_val in z.items():
            if abs(z_val) > self.threshold:
                anomalies.append(
                    {
                        "type": "error_spike",
                        "timestamp": str(ts),
                        "value": int(error_counts[ts]),
                        "z_score": round(float(z_val), 2),
                        "description": f"Error spike: {int(error_counts[ts])} errors (z={z_val:.2f})",
                    }
                )

        logger.info(f"Detected {len(anomalies)} error anomalies")
        return anomalies

    def detect_suspicious_ips(self, min_requests: int = 100) -> list[dict]:
        df = self._load_df()
        if df.empty:
            return []

        ip_counts = df["ip"].value_counts()
        z = self._z_scores(ip_counts)

        anomalies = []
        for ip, z_val in z.items():
            if z_val > self.threshold and ip_counts[ip] >= min_requests:
                anomalies.append(
                    {
                        "type": "suspicious_ip",
                        "ip": ip,
                        "value": int(ip_counts[ip]),
                        "z_score": round(float(z_val), 2),
                        "description": f"Suspicious IP {ip}: {int(ip_counts[ip])} requests (z={z_val:.2f})",
                    }
                )

        logger.info(f"Detected {len(anomalies)} suspicious IPs")
        return anomalies

    def detect_syslog_error_spikes(self, interval: str = "1h") -> list[dict]:
        entries = self.db.get_system_entries(level="error")
        if not entries:
            return []

        df = pd.DataFrame(entries)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        error_counts = df.set_index("timestamp").resample(interval).size()
        z = self._z_scores(error_counts)

        anomalies = []
        for ts, z_val in z.items():
            if abs(z_val) > self.threshold:
                anomalies.append(
                    {
                        "type": "syslog_error_spike",
                        "timestamp": str(ts),
                        "value": int(error_counts[ts]),
                        "z_score": round(float(z_val), 2),
                        "description": f"System error spike: {int(error_counts[ts])} errors (z={z_val:.2f})",
                    }
                )

        logger.info(f"Detected {len(anomalies)} system log error anomalies")
        return anomalies

    def detect_all(self) -> list[dict]:
        results = []
        results.extend(self.detect_traffic_spikes())
        results.extend(self.detect_error_spikes())
        results.extend(self.detect_suspicious_ips())
        results.extend(self.detect_syslog_error_spikes())

        for anomaly in results:
            self.db.insert_anomaly(
                type_=anomaly["type"],
                description=anomaly["description"],
                value=anomaly["value"],
                z_score=anomaly["z_score"],
            )

        return results
