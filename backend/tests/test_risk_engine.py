from backend.app.core.risk_engine import calculate_risk
from backend.app.models.threat_event import ThreatEvent


def test_calculate_risk_critical():
    event = ThreatEvent(
        event_type="login_attempt",
        source_ip="192.168.1.55",
        actor="unknown-user",
        region="eu-central-1",
        api_calls_last_minute=140,
        failed_logins=7,
        privileged_action=True,
    )

    risk = calculate_risk(event)

    assert risk.score == 100
    assert risk.severity == "critical"
    assert len(risk.reasons) >= 1


def test_calculate_risk_low():
    event = ThreatEvent(
        event_type="login_attempt",
        source_ip="10.0.0.10",
        actor="valid-user",
        region="us-east-1",
        api_calls_last_minute=5,
        failed_logins=0,
        privileged_action=False,
    )

    risk = calculate_risk(event)

    assert risk.score == 0
    assert risk.severity == "low"
    assert risk.reasons == []