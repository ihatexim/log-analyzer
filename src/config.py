import os

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
RATE_LIMIT = os.getenv("RATE_LIMIT", "60/minute")
_db_env = os.getenv("DB_PATH", "data/log_analyzer.db")
DB_PATH = _db_env if os.path.isabs(_db_env) else os.path.join(BASE_DIR, _db_env)
API_KEY = os.getenv("API_KEY", "")
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "2.0"))
LOG_DIR = os.path.join(BASE_DIR, "logs")
