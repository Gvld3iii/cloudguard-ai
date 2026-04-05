from backend.app.core.response_engine import decide_response
from backend.app.models.risk_score import RiskScore


def test_decide_response_block_ip():
    risk = RiskScore(
        score=95,
        severity="critical",
        reasons=["Privileged action detected"],
    )

    decision = decide_response(risk)

    assert decision.action == "block_ip"


def test_decide_response_send_alert():
    risk = RiskScore(
        score=65,
        severity="high",
        reasons=["Unusually high API call volume"],
    )

    decision = decide_response(risk)

    assert decision.action == "send_alert"


def test_decide_response_log_only():
    risk = RiskScore(
        score=10,
        severity="low",
        reasons=[],
    )

    decision = decide_response(risk)

    assert decision.action == "log_only"