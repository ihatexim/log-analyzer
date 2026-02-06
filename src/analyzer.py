import pandas as pd

from src.database import LogDatabase
from src.logger import get_logger

logger = get_logger(__name__)


class TrafficAnalyzer:
    def __init__(self, db: LogDatabase):
        self.db = db

    def _load_df(self, start=None, end=None) -> pd.DataFrame:
        entries = self.db.get_entries(start=start, end=end)
        if not entries:
            return pd.DataFrame()
        df = pd.DataFrame(entries)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def traffic_over_time(self, interval: str = "1h", start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["timestamp", "count"])
        result = df.set_index("timestamp").resample(interval).size().reset_index(name="count")
        return result

    def top_ips(self, limit: int = 10, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["ip", "count"])
        result = df["ip"].value_counts().head(limit).reset_index()
        result.columns = ["ip", "count"]
        return result

    def top_paths(self, limit: int = 10, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["path", "count"])
        result = df["path"].value_counts().head(limit).reset_index()
        result.columns = ["path", "count"]
        return result

    def status_distribution(self, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["status", "count"])
        result = df["status"].value_counts().reset_index()
        result.columns = ["status", "count"]
        return result.sort_values("status")

    def error_rate_over_time(self, interval: str = "1h", start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["timestamp", "error_rate"])
        df["is_error"] = df["status"] >= 400
        grouped = df.set_index("timestamp").resample(interval)
        total = grouped.size()
        errors = grouped["is_error"].sum()
        rate = (errors / total).fillna(0).reset_index(name="error_rate")
        return rate

    def hourly_pattern(self, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["hour", "count"])
        df["hour"] = df["timestamp"].dt.hour
        result = df.groupby("hour").size().reset_index(name="count")
        return result

    def bandwidth_over_time(self, interval: str = "1h", start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["timestamp", "bytes"])
        result = (
            df.set_index("timestamp")
            .resample(interval)["size"]
            .sum()
            .reset_index(name="bytes")
        )
        return result


class SystemLogAnalyzer:
    def __init__(self, db: LogDatabase):
        self.db = db

    def _load_df(self, start=None, end=None, level=None, source=None) -> pd.DataFrame:
        entries = self.db.get_system_entries(start=start, end=end, level=level, source=source)
        if not entries:
            return pd.DataFrame()
        df = pd.DataFrame(entries)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def events_over_time(self, interval: str = "1h", start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["timestamp", "count"])
        result = df.set_index("timestamp").resample(interval).size().reset_index(name="count")
        return result

    def level_distribution(self, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["level", "count"])
        result = df["level"].value_counts().reset_index()
        result.columns = ["level", "count"]
        return result

    def top_sources(self, limit: int = 10, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["source", "count"])
        result = df["source"].value_counts().head(limit).reset_index()
        result.columns = ["source", "count"]
        return result

    def errors_over_time(self, interval: str = "1h", start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end, level="error")
        if df.empty:
            return pd.DataFrame(columns=["timestamp", "count"])
        result = df.set_index("timestamp").resample(interval).size().reset_index(name="count")
        return result

    def hourly_pattern(self, start=None, end=None) -> pd.DataFrame:
        df = self._load_df(start, end)
        if df.empty:
            return pd.DataFrame(columns=["hour", "count"])
        df["hour"] = df["timestamp"].dt.hour
        result = df.groupby("hour").size().reset_index(name="count")
        return result
