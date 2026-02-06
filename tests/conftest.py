import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database import LogDatabase
from src.parser import AccessEntry, LogParser, SystemLogEntry

SAMPLE_NGINX_LINE = (
    '192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234 '
    '"https://google.com" "Mozilla/5.0"'
)

SAMPLE_APACHE_LINE = (
    '10.0.0.1 - - [15/Jan/2024:10:30:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 512'
)

SAMPLE_APACHE_ERROR_LINE = (
    '[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6'
)

SAMPLE_SYSLOG_LINE = (
    'Dec 24 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186'
)


@pytest.fixture
def parser():
    return LogParser()


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = LogDatabase(db_path=path)
    yield db
    os.unlink(path)


@pytest.fixture
def sample_entries():
    from datetime import datetime, timezone

    return [
        AccessEntry(
            ip="192.168.1.1",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            method="GET",
            path="/index.html",
            status=200,
            size=1024,
            referer="-",
            user_agent="Mozilla/5.0",
        ),
        AccessEntry(
            ip="192.168.1.2",
            timestamp=datetime(2024, 1, 15, 10, 5, 0, tzinfo=timezone.utc),
            method="POST",
            path="/api/login",
            status=401,
            size=256,
            referer="-",
            user_agent="curl/8.0",
        ),
        AccessEntry(
            ip="192.168.1.1",
            timestamp=datetime(2024, 1, 15, 10, 10, 0, tzinfo=timezone.utc),
            method="GET",
            path="/products",
            status=200,
            size=2048,
            referer="https://google.com",
            user_agent="Mozilla/5.0",
        ),
    ]


@pytest.fixture
def sample_system_entries():
    from datetime import datetime

    return [
        SystemLogEntry(
            timestamp=datetime(2024, 12, 24, 6, 55, 46),
            level="error",
            source="sshd",
            message="Invalid user webmaster from 173.234.31.186",
            hostname="LabSZ",
            pid=24200,
        ),
        SystemLogEntry(
            timestamp=datetime(2024, 12, 24, 7, 0, 0),
            level="info",
            source="sshd",
            message="Accepted password for root from 10.0.0.1",
            hostname="LabSZ",
            pid=24300,
        ),
        SystemLogEntry(
            timestamp=datetime(2024, 12, 24, 7, 5, 0),
            level="error",
            source="apache",
            message="mod_jk child workerEnv in error state 6",
        ),
    ]


@pytest.fixture
def temp_log_file():
    lines = [
        '192.168.1.1 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '192.168.1.2 - - [15/Jan/2024:10:01:00 +0000] "POST /api HTTP/1.1" 201 512 "-" "curl/8.0"',
        '10.0.0.1 - - [15/Jan/2024:10:02:00 +0000] "GET /404 HTTP/1.1" 404 256 "-" "Mozilla/5.0"',
        'invalid line here',
        '192.168.1.1 - - [15/Jan/2024:10:03:00 +0000] "GET /about HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    ]
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    yield path
    os.unlink(path)


@pytest.fixture
def temp_syslog_file():
    lines = [
        'Dec 24 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186',
        'Dec 24 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0',
        'Dec 24 07:00:00 LabSZ sshd[24300]: Accepted password for root from 10.0.0.1 port 22 ssh2',
        'invalid line',
        'Dec 24 07:05:00 LabSZ cron[1234]: pam_unix(cron:session): session opened for user root',
    ]
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    yield path
    os.unlink(path)


@pytest.fixture
def temp_apache_error_file():
    lines = [
        '[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties',
        '[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6',
        '[Sun Dec 04 04:51:08 2005] [notice] jk2_init() Found child 6725 in scoreboard slot 10',
    ]
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    yield path
    os.unlink(path)
