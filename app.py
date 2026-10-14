
from pathlib import Path

import json
import joblib
import pandas as pd
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field,  ConfigDict

import sqlite3
from datetime import datetime, timezone



BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "sentinelml_history.db"
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.joblib"

model = joblib.load(MODEL_PATH)

app = FastAPI(
    title="SentinelML",
    description="Machine Learning Network Intrusion Detection API",
    version="1.0.0",
)

def init_history_db():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS prediction_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                prediction INTEGER NOT NULL,
                label TEXT NOT NULL
            )
        """)


init_history_db()


class NetworkTraffic(BaseModel):
    model_config = ConfigDict(extra="forbid")
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

    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.execute(
            """
            INSERT INTO prediction_history (timestamp, prediction, label)
            VALUES (?, ?, ?)
            """,
            (timestamp, prediction, label)
        )
        prediction_id = cursor.lastrowid

    return {
        "id": prediction_id,
        "timestamp": timestamp,
        "prediction": prediction,
        "label": label
    }


@app.get("/history")
def get_history(limit: int = 20):
    limit = max(1, min(limit, 100))

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, timestamp, prediction, label
            FROM prediction_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    return {"history": [dict(row) for row in rows]}


@app.delete("/history")
def clear_history():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("DELETE FROM prediction_history")

    return {"message": "Prediction history cleared"}
