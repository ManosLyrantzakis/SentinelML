
from fastapi.testclient import TestClient

from app import app


client = TestClient(app)


def test_home_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_predict_endpoint():
    traffic = {
        "dur": 0.12,
        "proto": "tcp",
        "service": "http",
        "state": "FIN",
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 1200,
        "dbytes": 4500,
        "rate": 150.5,
        "sttl": 254,
        "dttl": 252,
        "sload": 80000,
        "dload": 300000,
        "sloss": 0,
        "dloss": 0,
        "sinpkt": 0.01,
        "dinpkt": 0.02,
        "sjit": 0,
        "djit": 0,
        "swin": 255,
        "stcpb": 1000,
        "dtcpb": 2000,
        "dwin": 255,
        "tcprtt": 0.03,
        "synack": 0.01,
        "ackdat": 0.02,
        "smean": 120,
        "dmean": 562,
        "trans_depth": 1,
        "response_body_len": 0,
        "ct_srv_src": 2,
        "ct_state_ttl": 1,
        "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 1,
        "ct_src_ltm": 1,
        "ct_srv_dst": 2,
        "is_sm_ips_ports": 0,
    }

    response = client.post("/predict", json=traffic)

    assert response.status_code == 200

    result = response.json()

    assert result["prediction"] in [0, 1]
    assert result["label"] in ["Normal", "Attack"]

    expected_label = "Attack" if result["prediction"] == 1 else "Normal"
    assert result["label"] == expected_label


def test_predict_rejects_missing_fields():
    response = client.post("/predict", json={})

    assert response.status_code == 422
