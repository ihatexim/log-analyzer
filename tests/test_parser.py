from src.parser import AccessEntry, SystemLogEntry
from tests.conftest import (
    SAMPLE_APACHE_ERROR_LINE,
    SAMPLE_APACHE_LINE,
    SAMPLE_NGINX_LINE,
    SAMPLE_SYSLOG_LINE,
)


def test_parse_nginx_line(parser):
    entry = parser.parse_line(SAMPLE_NGINX_LINE)
    assert entry is not None
    assert isinstance(entry, AccessEntry)
    assert entry.ip == "192.168.1.1"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.status == 200
    assert entry.size == 1234
    assert entry.referer == "https://google.com"
    assert entry.user_agent == "Mozilla/5.0"


def test_parse_apache_line(parser):
    entry = parser.parse_line(SAMPLE_APACHE_LINE)
    assert entry is not None
    assert isinstance(entry, AccessEntry)
    assert entry.ip == "10.0.0.1"
    assert entry.method == "POST"
    assert entry.path == "/api/login"
    assert entry.status == 401
    assert entry.size == 512


def test_parse_apache_error_line(parser):
    entry = parser.parse_line(SAMPLE_APACHE_ERROR_LINE)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "error"
    assert entry.source == "apache"
    assert "mod_jk" in entry.message


def test_parse_syslog_line(parser):
    entry = parser.parse_line(SAMPLE_SYSLOG_LINE)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.hostname == "LabSZ"
    assert entry.source == "sshd"
    assert entry.pid == 24200
    assert entry.level == "error"
    assert "Invalid user" in entry.message


def test_parse_invalid_line(parser):
    assert parser.parse_line("invalid log line") is None
    assert parser.parse_line("") is None
    assert parser.parse_line("   ") is None


def test_parse_file(parser, temp_log_file):
    entries = parser.parse_file(temp_log_file)
    assert len(entries) == 4


def test_parse_syslog_file(parser, temp_syslog_file):
    entries = parser.parse_file(temp_syslog_file)
    assert len(entries) == 4
    assert all(isinstance(e, SystemLogEntry) for e in entries)


def test_parse_apache_error_file(parser, temp_apache_error_file):
    entries = parser.parse_file(temp_apache_error_file)
    assert len(entries) == 3
    assert all(isinstance(e, SystemLogEntry) for e in entries)


def test_parse_file_by_type(parser, temp_log_file):
    access, system = parser.parse_file_by_type(temp_log_file)
    assert len(access) == 4
    assert len(system) == 0


def test_parse_file_by_type_syslog(parser, temp_syslog_file):
    access, system = parser.parse_file_by_type(temp_syslog_file)
    assert len(access) == 0
    assert len(system) == 4


def test_detect_format_nginx(parser, temp_log_file):
    fmt = parser.detect_format(temp_log_file)
    assert fmt == "nginx_combined"


def test_detect_format_syslog(parser, temp_syslog_file):
    fmt = parser.detect_format(temp_syslog_file)
    assert fmt == "syslog"


def test_detect_format_apache_error(parser, temp_apache_error_file):
    fmt = parser.detect_format(temp_apache_error_file)
    assert fmt == "apache_error"


def test_parse_hdfs_line(parser):
    line = '081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating'
    entry = parser.parse_line(line)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "info"
    assert entry.pid == 148
    assert "PacketResponder" in entry.message


def test_parse_hadoop_line(parser):
    line = '2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster'
    entry = parser.parse_line(line)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "info"
    assert entry.source == "MRAppMaster"


def test_parse_spark_line(parser):
    line = '17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered signal handlers'
    entry = parser.parse_line(line)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "info"
    assert entry.source == "CoarseGrainedExecutorBackend"


def test_parse_zookeeper_line(parser):
    line = '2015-07-29 17:41:44,747 - INFO  [QuorumPeer[myid=1]/0:0:0:0:0:0:0:0:2181:FastLeaderElection@774] - Notification time out: 3200'
    entry = parser.parse_line(line)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "info"


def test_parse_windows_line(parser):
    line = '2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack v6.1.7601.23505'
    entry = parser.parse_line(line)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "info"
    assert entry.source == "CBS"


def test_parse_openstack_line(parser):
    line = 'nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO nova.osapi_compute.wsgi.server [req-38101a0b] 10.11.10.1 "GET /v2/test"'
    entry = parser.parse_line(line)
    assert entry is not None
    assert isinstance(entry, SystemLogEntry)
    assert entry.level == "info"
    assert entry.pid == 25746
