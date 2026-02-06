import os
import tempfile
from datetime import datetime, timedelta, timezone

from src.anomaly import AnomalyDetector
from src.database import LogDatabase
from src.parser import AccessEntry


def _make_entries(count: int, base_hour: int, ip: str = "192.168.1.1", status: int = 200):
    base = datetime(2024, 1, 15, base_hour, 0, 0, tzinfo=timezone.utc)
    entries = []
    for i in range(count):
        entries.append(
            AccessEntry(
                ip=ip,
                timestamp=base + timedelta(seconds=i * 10),
                method="GET",
                path="/",
                status=status,
                size=1024,
            )
        )
    return entries


def test_detect_traffic_spikes():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = LogDatabase(db_path=path)

    normal = []
    for h in range(0, 20):
        normal.extend(_make_entries(10, h))

    spike = _make_entries(200, 21)
    db.insert_entries(normal + spike)

    detector = AnomalyDetector(db, threshold=2.0)
    anomalies = detector.detect_traffic_spikes()
    assert len(anomalies) > 0
    assert any(a["type"] == "traffic_spike" for a in anomalies)

    os.unlink(path)


def test_detect_error_spikes():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = LogDatabase(db_path=path)

    normal = []
    for h in range(0, 20):
        normal.extend(_make_entries(10, h, status=200))

    errors = _make_entries(50, 21, status=500)
    db.insert_entries(normal + errors)

    detector = AnomalyDetector(db, threshold=2.0)
    anomalies = detector.detect_error_spikes()
    assert len(anomalies) > 0
    assert any(a["type"] == "error_spike" for a in anomalies)

    os.unlink(path)


def test_detect_suspicious_ips():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = LogDatabase(db_path=path)

    normal = []
    for i in range(1, 21):
        normal.extend(_make_entries(5, 10, ip=f"192.168.1.{i}"))

    suspicious = _make_entries(200, 10, ip="45.33.32.156")
    db.insert_entries(normal + suspicious)

    detector = AnomalyDetector(db, threshold=2.0)
    anomalies = detector.detect_suspicious_ips(min_requests=50)
    assert len(anomalies) > 0
    assert anomalies[0]["ip"] == "45.33.32.156"

    os.unlink(path)


def test_no_anomalies_on_empty(temp_db):
    detector = AnomalyDetector(temp_db)
    assert detector.detect_all() == []
