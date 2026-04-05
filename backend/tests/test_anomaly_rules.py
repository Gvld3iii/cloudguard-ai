from backend.app.core.anomaly_rules import evaluate_anomalies
from backend.app.models.threat_event import ThreatEvent


def test_evaluate_anomalies_detects_multiple_reasons():
    event = ThreatEvent(
        event_type="admin_action",
        source_ip="172.16.0.8",
        actor="suspicious-admin",
        region="ap-south-1",
        api_calls_last_minute=150,
        failed_logins=8,
        privileged_action=True,
    )

    reasons = evaluate_anomalies(event)

    assert "High number of failed login attempts" in reasons
    assert "Unusually high API call volume" in reasons
    assert "Privileged action detected" in reasons
    assert "Login or action from unusual region" in reasons


def test_evaluate_anomalies_returns_empty_for_normal_event():
    event = ThreatEvent(
        event_type="read_only_action",
        source_ip="10.0.0.20",
        actor="normal-user",
        region="us-west-2",
        api_calls_last_minute=10,
        failed_logins=0,
        privileged_action=False,
    )

    reasons = evaluate_anomalies(event)

    assert reasons == []