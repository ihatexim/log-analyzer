import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Union

from src.logger import get_logger

logger = get_logger(__name__)

NGINX_COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

APACHE_COMMON = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

APACHE_ERROR = re.compile(
    r'\[(?P<timestamp>\w+ \w+ \d+ \d+:\d+:\d+ \d+)\] '
    r'\[(?P<level>\w+)\] '
    r'(?P<message>.*)'
)

SYSLOG = re.compile(
    r'(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) '
    r'(?P<hostname>\S+) '
    r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)'
)

HDFS = re.compile(
    r'(?P<date>\d{6}) (?P<time>\d{6}) '
    r'(?P<pid>\d+) (?P<level>\w+) '
    r'(?P<source>[^:]+):\s*'
    r'(?P<message>.*)'
)

HADOOP = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} '
    r'(?P<level>\w+)\s+'
    r'\[(?P<thread>[^\]]+)\]\s+'
    r'(?P<source>\S+):\s*'
    r'(?P<message>.*)'
)

SPARK = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'(?P<level>\w+)\s+'
    r'(?P<source>[^:]+):\s*'
    r'(?P<message>.*)'
)

ZOOKEEPER = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} '
    r'- (?P<level>\w+)\s+'
    r'\[(?P<source>.+?)\]\s*-\s*'
    r'(?P<message>.*)'
)

WINDOWS = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*'
    r'(?P<level>\w+)\s+'
    r'(?P<source>\w+)\s+'
    r'(?P<message>.*)'
)

OPENSTACK = re.compile(
    r'(?:\S+\s+)?'
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+\s+'
    r'(?P<pid>\d+)\s+'
    r'(?P<level>\w+)\s+'
    r'(?P<source>\S+)\s+'
    r'(?:\[(?P<request_id>[^\]]*)\]\s+)?'
    r'(?P<message>.*)'
)

ACCESS_TIMESTAMP = "%d/%b/%Y:%H:%M:%S %z"
APACHE_ERROR_TIMESTAMP = "%a %b %d %H:%M:%S %Y"
SYSLOG_TIMESTAMP = "%b %d %H:%M:%S"


@dataclass
class AccessEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    referer: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class SystemLogEntry:
    timestamp: datetime
    level: str
    source: str
    message: str
    hostname: Optional[str] = None
    pid: Optional[int] = None


LogEntry = Union[AccessEntry, SystemLogEntry]


class LogParser:
    def __init__(self):
        self.access_patterns = [
            ("nginx_combined", NGINX_COMBINED),
            ("apache_common", APACHE_COMMON),
        ]
        self.system_patterns = [
            ("apache_error", APACHE_ERROR),
            ("syslog", SYSLOG),
            ("hdfs", HDFS),
            ("zookeeper", ZOOKEEPER),
            ("hadoop", HADOOP),
            ("spark", SPARK),
            ("windows", WINDOWS),
            ("openstack", OPENSTACK),
        ]

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        entry = self._try_access(line)
        if entry:
            return entry

        entry = self._try_system(line)
        if entry:
            return entry

        return None

    def _try_access(self, line: str) -> Optional[AccessEntry]:
        for _, pattern in self.access_patterns:
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                try:
                    ts = datetime.strptime(data["timestamp"], ACCESS_TIMESTAMP)
                except ValueError:
                    return None
                return AccessEntry(
                    ip=data["ip"],
                    timestamp=ts,
                    method=data["method"],
                    path=data["path"],
                    status=int(data["status"]),
                    size=int(data["size"]),
                    referer=data.get("referer"),
                    user_agent=data.get("user_agent"),
                )
        return None

    def _try_system(self, line: str) -> Optional[SystemLogEntry]:
        match = APACHE_ERROR.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], APACHE_ERROR_TIMESTAMP)
            except ValueError:
                return None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"],
                source="apache",
                message=data["message"],
            )

        match = SYSLOG.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], SYSLOG_TIMESTAMP)
                ts = ts.replace(year=datetime.now().year)
            except ValueError:
                return None
            pid = int(data["pid"]) if data.get("pid") else None
            return SystemLogEntry(
                timestamp=ts,
                level=self._extract_syslog_level(data["message"]),
                source=data["service"],
                message=data["message"],
                hostname=data["hostname"],
                pid=pid,
            )

        match = ZOOKEEPER.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"].lower(),
                source=data["source"].split(":")[0] if ":" in data["source"] else data["source"],
                message=data["message"],
            )

        match = HADOOP.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"].lower(),
                source=data["source"].split(".")[-1] if "." in data["source"] else data["source"],
                message=data["message"],
            )

        match = OPENSTACK.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            pid = int(data["pid"]) if data.get("pid") else None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"].lower(),
                source=data["source"].split(".")[-1] if "." in data["source"] else data["source"],
                message=data["message"],
                pid=pid,
            )

        match = SPARK.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], "%y/%m/%d %H:%M:%S")
            except ValueError:
                return None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"].lower(),
                source=data["source"].split(".")[-1] if "." in data["source"] else data["source"],
                message=data["message"],
            )

        match = WINDOWS.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"].lower(),
                source=data["source"],
                message=data["message"],
            )

        match = HDFS.match(line)
        if match:
            data = match.groupdict()
            try:
                ts = datetime.strptime(f"{data['date']} {data['time']}", "%y%m%d %H%M%S")
            except ValueError:
                return None
            pid = int(data["pid"]) if data.get("pid") else None
            return SystemLogEntry(
                timestamp=ts,
                level=data["level"].lower(),
                source=data["source"].split(".")[-1] if "." in data["source"] else data["source"],
                message=data["message"],
                pid=pid,
            )

        return None

    def _extract_syslog_level(self, message: str) -> str:
        msg_lower = message.lower()
        if "error" in msg_lower or "fail" in msg_lower or "invalid" in msg_lower:
            return "error"
        if "warn" in msg_lower:
            return "warning"
        if "accepted" in msg_lower or "success" in msg_lower:
            return "info"
        return "info"

    def parse_file(self, filepath: str) -> list[LogEntry]:
        entries = []
        failed = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                entry = self.parse_line(line)
                if entry:
                    entries.append(entry)
                else:
                    failed += 1

        logger.info(f"Parsed {len(entries)} entries, {failed} failed from {filepath}")
        return entries

    def parse_file_by_type(self, filepath: str) -> tuple[list[AccessEntry], list[SystemLogEntry]]:
        access_entries = []
        system_entries = []
        failed = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                entry = self._try_access(line)
                if entry:
                    access_entries.append(entry)
                    continue

                entry = self._try_system(line)
                if entry:
                    system_entries.append(entry)
                    continue

                failed += 1

        logger.info(
            f"Parsed {len(access_entries)} access + {len(system_entries)} system entries, "
            f"{failed} failed from {filepath}"
        )
        return access_entries, system_entries

    def detect_format(self, filepath: str) -> Optional[str]:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                for name, pattern in self.access_patterns:
                    if pattern.match(line):
                        return name
                for name, pattern in self.system_patterns:
                    if pattern.match(line):
                        return name
        return None
