from src.analyzer import TrafficAnalyzer


def test_traffic_over_time(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    analyzer = TrafficAnalyzer(temp_db)
    df = analyzer.traffic_over_time("1h")
    assert not df.empty
    assert "timestamp" in df.columns
    assert "count" in df.columns


def test_top_ips(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    analyzer = TrafficAnalyzer(temp_db)
    df = analyzer.top_ips(5)
    assert len(df) == 2
    assert df.iloc[0]["ip"] == "192.168.1.1"


def test_top_paths(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    analyzer = TrafficAnalyzer(temp_db)
    df = analyzer.top_paths(5)
    assert len(df) == 3


def test_status_distribution(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    analyzer = TrafficAnalyzer(temp_db)
    df = analyzer.status_distribution()
    assert not df.empty


def test_hourly_pattern(temp_db, sample_entries):
    temp_db.insert_entries(sample_entries)
    analyzer = TrafficAnalyzer(temp_db)
    df = analyzer.hourly_pattern()
    assert not df.empty
    assert "hour" in df.columns


def test_empty_data(temp_db):
    analyzer = TrafficAnalyzer(temp_db)
    assert analyzer.traffic_over_time().empty
    assert analyzer.top_ips().empty
    assert analyzer.top_paths().empty
    assert analyzer.status_distribution().empty
    assert analyzer.hourly_pattern().empty
    assert analyzer.bandwidth_over_time().empty
    assert analyzer.error_rate_over_time().empty
