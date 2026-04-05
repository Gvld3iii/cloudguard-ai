from backend.app.core.anomaly_rules import evaluate_anomalies
from backend.app.logger import get_logger
from backend.app.models.risk_score import RiskScore
from backend.app.models.threat_event import ThreatEvent
from backend.app.utils.helpers import clamp_score, severity_from_score

logger = get_logger("risk_engine")


def calculate_risk(event: ThreatEvent) -> RiskScore:
    score = 0
    reasons = evaluate_anomalies(event)

    logger.info(f"Processing event from IP: {event.source_ip}")
    logger.info(f"Detected anomaly reasons: {reasons}")

    if event.failed_logins >= 5:
        score += 30

    if event.api_calls_last_minute >= 100:
        score += 30

    if event.privileged_action:
        score += 25

    if event.region and event.region.lower() not in ["us-east-1", "us-west-2"]:
        score += 15

    score = clamp_score(score)
    severity = severity_from_score(score)

    logger.info(f"Calculated risk score: {score}")
    logger.info(f"Assigned severity: {severity}")

    return RiskScore(
        score=score,
        severity=severity,
        reasons=reasons,
    )