import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse

from src.analyzer import SystemLogAnalyzer, TrafficAnalyzer
from src.anomaly import AnomalyDetector
from src.config import API_HOST, API_KEY, API_PORT, RATE_LIMIT
from src.database import LogDatabase
from src.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title="Log Analyzer API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(key: str = Security(api_key_header)):
    if not API_KEY:
        return
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


db = LogDatabase()
analyzer = TrafficAnalyzer(db)
sys_analyzer = SystemLogAnalyzer(db)
detector = AnomalyDetector(db)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "access_entries": db.get_entry_count(),
        "system_entries": db.get_system_entry_count(),
    }


@app.get("/summary", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def summary(request: Request):
    count = db.get_entry_count()
    if count == 0:
        return {"message": "No data available"}
    return db.get_summary()


@app.get("/summary/system", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def system_summary(request: Request):
    count = db.get_system_entry_count()
    if count == 0:
        return {"message": "No data available"}
    return db.get_system_summary()


@app.get("/top/ips", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def top_ips(request: Request, limit: int = 10):
    return db.get_top_ips(limit)


@app.get("/top/paths", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def top_paths(request: Request, limit: int = 10):
    return db.get_top_paths(limit)


@app.get("/top/sources", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def top_sources(request: Request, limit: int = 10):
    return db.get_top_sources(limit)


@app.get("/status-codes", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def status_codes(request: Request):
    return db.get_status_distribution()


@app.get("/levels", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def levels(request: Request):
    return db.get_level_distribution()


@app.get("/traffic", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def traffic(request: Request, interval: str = "1h"):
    df = analyzer.traffic_over_time(interval)
    if df.empty:
        return []
    df["timestamp"] = df["timestamp"].astype(str)
    return df.to_dict(orient="records")


@app.get("/errors", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def errors(request: Request, interval: str = "1h"):
    df = analyzer.error_rate_over_time(interval)
    if df.empty:
        return []
    df["timestamp"] = df["timestamp"].astype(str)
    return df.to_dict(orient="records")


@app.get("/system/events", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def system_events(request: Request, interval: str = "1h"):
    df = sys_analyzer.events_over_time(interval)
    if df.empty:
        return []
    df["timestamp"] = df["timestamp"].astype(str)
    return df.to_dict(orient="records")


@app.get("/system/errors", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def system_errors(request: Request, interval: str = "1h"):
    df = sys_analyzer.errors_over_time(interval)
    if df.empty:
        return []
    df["timestamp"] = df["timestamp"].astype(str)
    return df.to_dict(orient="records")


@app.get("/anomalies", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT)
def anomalies(request: Request):
    return detector.detect_all()


if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting API at {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=API_PORT)
