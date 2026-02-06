def test_insert_and_count(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    assert temp_db.get_entry_count() == 3


def test_get_summary(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    summary = temp_db.get_summary()
    assert summary["total"] == 3
    assert summary["unique_ips"] == 2


def test_get_top_ips(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    top = temp_db.get_top_ips(2)
    assert len(top) == 2
    assert top[0]["ip"] == "192.168.1.1"
    assert top[0]["count"] == 2


def test_get_top_paths(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    top = temp_db.get_top_paths(5)
    assert len(top) == 3


def test_get_status_distribution(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    dist = temp_db.get_status_distribution()
    statuses = {d["status"]: d["count"] for d in dist}
    assert statuses[200] == 2
    assert statuses[401] == 1


def test_reset(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    temp_db.reset()
    assert temp_db.get_entry_count() == 0


def test_insert_anomaly(temp_db):
    temp_db.insert_anomaly("traffic_spike", "test anomaly", 500.0, 3.5)
    anomalies = temp_db.get_anomalies()
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "traffic_spike"
    assert anomalies[0]["z_score"] == 3.5


def test_insert_system_entries(temp_db, sample_system_entries):
    temp_db.insert_system_entries(sample_system_entries)
    assert temp_db.get_system_entry_count() == 3


def test_system_summary(temp_db, sample_system_entries):
    temp_db.insert_system_entries(sample_system_entries)
    summary = temp_db.get_system_summary()
    assert summary["total"] == 3
    assert summary["unique_sources"] == 2


def test_level_distribution(temp_db, sample_system_entries):
    temp_db.insert_system_entries(sample_system_entries)
    dist = temp_db.get_level_distribution()
    levels = {d["level"]: d["count"] for d in dist}
    assert levels["error"] == 2
    assert levels["info"] == 1


def test_top_sources(temp_db, sample_system_entries):
    temp_db.insert_system_entries(sample_system_entries)
    top = temp_db.get_top_sources(5)
    assert top[0]["source"] == "sshd"
    assert top[0]["count"] == 2


def test_reset_includes_system(temp_db, sample_system_entries):
    temp_db.insert_system_entries(sample_system_entries)
    temp_db.reset()
    assert temp_db.get_system_entry_count() == 0
