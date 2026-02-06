import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(BASE_DIR, "logs", "access.log")

IPS = [
    "192.168.1." + str(i) for i in range(1, 51)
] + [
    "10.0.0." + str(i) for i in range(1, 21)
] + [
    "172.16.0." + str(i) for i in range(1, 11)
]

ATTACKER_IPS = ["45.33.32.156", "104.236.198.48", "185.220.101.33"]

PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/api/v1/users",
    "/api/v1/products", "/api/v1/orders", "/api/v1/auth/login", "/api/v1/auth/register",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png",
    "/blog", "/blog/post-1", "/blog/post-2", "/search", "/sitemap.xml",
    "/robots.txt", "/favicon.ico", "/admin", "/admin/dashboard",
    "/api/v1/health", "/api/v1/stats", "/docs", "/api/v1/products/1",
    "/api/v1/products/2", "/api/v1/users/profile", "/api/v1/cart",
]

METHODS = ["GET", "GET", "GET", "GET", "POST", "PUT", "DELETE"]

STATUS_WEIGHTS = {
    200: 70, 201: 5, 301: 3, 304: 8, 400: 4, 401: 2, 403: 2, 404: 4, 500: 1, 502: 0.5, 503: 0.5,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "python-requests/2.31.0",
    "curl/8.4.0",
]

REFERERS = [
    "-", "-", "-",
    "https://www.google.com/", "https://www.bing.com/",
    "https://example.com/", "https://example.com/products",
]


def weighted_choice(weights: dict):
    items = list(weights.keys())
    w = list(weights.values())
    return random.choices(items, weights=w, k=1)[0]


def generate_line(ts: datetime, is_anomaly: bool = False) -> str:
    if is_anomaly:
        ip = random.choice(ATTACKER_IPS)
        status = random.choice([400, 401, 403, 404, 500])
        path = random.choice(["/admin", "/api/v1/auth/login", "/wp-admin", "/.env", "/phpmyadmin"])
    else:
        ip = random.choice(IPS)
        status = weighted_choice(STATUS_WEIGHTS)
        path = random.choice(PATHS)

    method = random.choice(METHODS)
    size = random.randint(200, 50000)
    ua = random.choice(USER_AGENTS)
    ref = random.choice(REFERERS)

    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S %z")

    return f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def generate(num_lines: int = 10000):
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    start = datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=7)
    total_seconds = int((end - start).total_seconds())

    anomaly_start_1 = start + timedelta(days=2, hours=14)
    anomaly_end_1 = anomaly_start_1 + timedelta(hours=2)
    anomaly_start_2 = start + timedelta(days=5, hours=3)
    anomaly_end_2 = anomaly_start_2 + timedelta(hours=1)

    lines = []
    for _ in range(num_lines):
        offset = random.randint(0, total_seconds)
        ts = start + timedelta(seconds=offset)

        is_anomaly = (anomaly_start_1 <= ts <= anomaly_end_1) or (
            anomaly_start_2 <= ts <= anomaly_end_2
        )

        if is_anomaly and random.random() < 0.6:
            lines.append((ts, generate_line(ts, is_anomaly=True)))
        else:
            lines.append((ts, generate_line(ts, is_anomaly=False)))

    lines.sort(key=lambda x: x[0])

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for _, line in lines:
            f.write(line + "\n")

    print(f"Generated {num_lines} log entries -> {OUTPUT}")


if __name__ == "__main__":
    generate()
