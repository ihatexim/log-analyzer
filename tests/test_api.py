import os
import tempfile
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.parser import AccessEntry, SystemLogEntry


@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    from src.database import LogDatabase

    temp_db = LogDatabase(db_path=path)

    from src import api as api_module

    api_module.db = temp_db
    api_module.analyzer = api_module.TrafficAnalyzer(temp_db)
    api_module.sys_analyzer = api_module.SystemLogAnalyzer(temp_db)
    api_module.detector = api_module.AnomalyDetector(temp_db)

    yield TestClient(api_module.app), temp_db, path

    os.unlink(path)


@pytest.fixture
def client_with_data(client):
    test_client, db, path = client
    entries = [
        AccessEntry(
            ip="192.168.1.1",
            timestamp=datetime(2024, 1, 15, 10, i, 0, tzinfo=timezone.utc),
            method="GET",
            path="/index.html",
            status=200,
            size=1024,
        )
        for i in range(5)
    ]
    db.insert_entries(entries)
    return test_client


@pytest.fixture
def client_with_system_data(client):
    test_client, db, path = client
    entries = [
        SystemLogEntry(
            timestamp=datetime(2024, 12, 24, 6, i, 0),
            level="error" if i % 2 == 0 else "info",
            source="sshd",
            message=f"test message {i}",
            hostname="server1",
            pid=1000 + i,
        )
        for i in range(5)
    ]
    db.insert_system_entries(entries)
    return test_client


def test_health(client):
    test_client, _, _ = client
    r = test_client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_summary_empty(client):
    test_client, _, _ = client
    r = test_client.get("/summary")
    assert r.status_code == 200
    assert r.json()["message"] == "No data available"


def test_summary_with_data(client_with_data):
    r = client_with_data.get("/summary")
    assert r.status_code == 200
    assert r.json()["total"] == 5


def test_top_ips(client_with_data):
    r = client_with_data.get("/top/ips")
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 1


def test_top_paths(client_with_data):
    r = client_with_data.get("/top/paths")
    assert r.status_code == 200


def test_status_codes(client_with_data):
    r = client_with_data.get("/status-codes")
    assert r.status_code == 200


def test_traffic(client_with_data):
    r = client_with_data.get("/traffic")
    assert r.status_code == 200


def test_errors(client_with_data):
    r = client_with_data.get("/errors")
    assert r.status_code == 200


def test_anomalies(client_with_data):
    r = client_with_data.get("/anomalies")
    assert r.status_code == 200


def test_system_summary(client_with_system_data):
    r = client_with_system_data.get("/summary/system")
    assert r.status_code == 200
    assert r.json()["total"] == 5


def test_system_summary_empty(client):
    test_client, _, _ = client
    r = test_client.get("/summary/system")
    assert r.status_code == 200
    assert r.json()["message"] == "No data available"


def test_top_sources(client_with_system_data):
    r = client_with_system_data.get("/top/sources")
    assert r.status_code == 200
    assert len(r.json()) >= 1


def test_levels(client_with_system_data):
    r = client_with_system_data.get("/levels")
    assert r.status_code == 200
    assert len(r.json()) >= 1


def test_system_events(client_with_system_data):
    r = client_with_system_data.get("/system/events")
    assert r.status_code == 200


def test_system_errors(client_with_system_data):
    r = client_with_system_data.get("/system/errors")
    assert r.status_code == 200
