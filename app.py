
from pathlib import Path

import json
import joblib
import pandas as pd
import logging
import secrets
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field,  ConfigDict
from psycopg.rows import dict_row
import os
import psycopg
import sqlite3
from datetime import datetime, timezone


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("sentinelml")

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "sentinelml_history.db"
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.joblib"
DATABASE_URL = os.getenv("DATABASE_URL")
HISTORY_ADMIN_TOKEN = os.getenv("HISTORY_ADMIN_TOKEN")

model = joblib.load(MODEL_PATH)

app = FastAPI(
    title="SentinelML",
    description="Machine Learning Network Intrusion Detection API",
    version="1.0.0",
)

def init_history_db():
    if DATABASE_URL:
        print("Database mode: PostgreSQL (Neon)")
        try:
            with psycopg.connect(DATABASE_URL) as connection:
                db_info = connection.execute(
                    "SELECT current_database(), current_schema()"
                ).fetchone()

                print(
                    f"PostgreSQL connected: database={db_info[0]}, schema={db_info[1]}"
                )

                connection.execute("""
                    CREATE TABLE IF NOT EXISTS prediction_history (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        prediction INTEGER NOT NULL,
                        label TEXT NOT NULL
                    )
                """)

            print("PostgreSQL history table initialized successfully")

        except Exception:
            logger.exception("Failed to initialize PostgreSQL history table")
            raise

    else:
        print("Database mode: SQLite")
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS prediction_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    prediction INTEGER NOT NULL,
                    label TEXT NOT NULL
                )
            """)
        print("SQLite history table initialized successfully")


init_history_db()

class NetworkTraffic(BaseModel):
    model_config = ConfigDict(
    extra="forbid",
    allow_inf_nan=False,
)
    dur: float = Field(ge=0)
    proto: str
    service: str
    state: str
    spkts: int = Field(ge=0)
    dpkts: int = Field(ge=0)
    sbytes: int = Field(ge=0)
    dbytes: int = Field(ge=0)
    rate: float
    sttl: int
    dttl: int
    sload: float
    dload: float
    sloss: float
    dloss: float
    sinpkt: float
    dinpkt: float
    sjit: float
    djit: float
    swin: int
    stcpb: int
    dtcpb: int
    dwin: int
    tcprtt: float
    synack: float
    ackdat: float
    smean: int
    dmean: int
    trans_depth: int
    response_body_len: int
    ct_srv_src: int
    ct_state_ttl: int
    ct_dst_ltm: int
    ct_src_dport_ltm: int
    ct_dst_sport_ltm: int
    ct_dst_src_ltm: int
    is_ftp_login: int
    ct_ftp_cmd: int
    ct_flw_http_mthd: int
    ct_src_ltm: int
    ct_srv_dst: int
    is_sm_ips_ports: int


@app.get("/")
def home():
    return {
        "message": "Welcome to SentinelML",
        "status": "running",
    }
    
@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(BASE_DIR / "dashboard.html")

@app.get("/metrics")
def get_metrics():
    metrics_path = BASE_DIR / "reports" / "unsw_test_metrics.json"

    if not metrics_path.exists():
        return {
            "error": "Metrics report not found. Run evaluate_model.py first."
        }

    with metrics_path.open("r", encoding="utf-8") as file:
        return json.load(file)
    

@app.post("/predict")
def predict(traffic: NetworkTraffic):
    features = pd.DataFrame([traffic.model_dump()])
    prediction = int(model.predict(features)[0])
    label = "Attack" if prediction == 1 else "Normal"
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        if DATABASE_URL:
            with psycopg.connect(DATABASE_URL) as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO prediction_history
                        (timestamp, prediction, label)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (timestamp, prediction, label),
                )
                prediction_id = cursor.fetchone()[0]
        else:
            with sqlite3.connect(DATABASE_PATH) as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO prediction_history
                        (timestamp, prediction, label)
                    VALUES (?, ?, ?)
                    """,
                    (timestamp, prediction, label),
                )
                prediction_id = cursor.lastrowid

    except (sqlite3.Error, psycopg.Error):
        logger.exception("Failed to save prediction history")
        raise

    logger.info(
        "Prediction saved | id=%s | prediction=%s | label=%s",
        prediction_id,
        prediction,
        label,
    )

    return {
        "id": prediction_id,
        "timestamp": timestamp,
        "prediction": prediction,
        "label": label,
    }

@app.get("/history")
def get_history(limit: int = 20):
    limit = max(1, min(limit, 100))

    if DATABASE_URL:
        with psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row,
        ) as connection:
            rows = connection.execute(
                """
                SELECT id, timestamp, prediction, label
                FROM prediction_history
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            ).fetchall()
    else:
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, timestamp, prediction, label
                FROM prediction_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    return {"history": [dict(row) for row in rows]}


@app.delete("/history")
def clear_history(authorization: str | None = Header(default=None)):
    if not HISTORY_ADMIN_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="History deletion is not configured.",
        )

    expected = f"Bearer {HISTORY_ADMIN_TOKEN}"

    if not authorization or not secrets.compare_digest(
        authorization, expected
    ):
        raise HTTPException(
            status_code=401,
            detail="Not authorized.",
        )

    if DATABASE_URL:
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute("DELETE FROM prediction_history")
    else:
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.execute("DELETE FROM prediction_history")

    logger.info("Prediction history cleared by authorized request")
    return {"message": "Prediction history cleared"}
