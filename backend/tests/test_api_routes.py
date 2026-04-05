from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_root_route():
    response = client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "environment" in data
    assert "docs_url" in data


def test_health_route():
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_simulate_route_critical():
    payload = {
        "event_type": "login_attempt",
        "source_ip": "192.168.1.55",
        "actor": "unknown-user",
        "region": "eu-central-1",
        "api_calls_last_minute": 140,
        "failed_logins": 7,
        "privileged_action": True,
    }

    response = client.post("/simulate", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["score"] == 100
    assert data["decision"]["action"] == "block_ip"


def test_threats_analyze_route_low():
    payload = {
        "event_type": "read_only_action",
        "source_ip": "10.0.0.10",
        "actor": "normal-user",
        "region": "us-east-1",
        "api_calls_last_minute": 5,
        "failed_logins": 0,
        "privileged_action": False,
    }

    response = client.post("/threats/analyze", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["severity"] == "low"
    assert data["decision"]["action"] == "log_only"