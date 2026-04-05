from backend.app.logger import get_logger
from backend.app.models.alert import AlertDecision
from backend.app.models.risk_score import RiskScore
from backend.app.models.threat_event import ThreatEvent

logger = get_logger("sns_service")


def send_security_alert(
    event: ThreatEvent,
    risk: RiskScore,
    decision: AlertDecision,
) -> dict:
    logger.info(
        f"Stub SNS alert for source_ip={event.source_ip}, action={decision.action}"
    )

    alert_payload = {
        "subject": f"CloudGuard AI Alert: {risk.severity.upper()} risk detected",
        "message": {
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "actor": event.actor,
            "risk_score": risk.score,
            "severity": risk.severity,
            "reasons": risk.reasons,
            "recommended_action": decision.action,
        },
        "delivery": "stubbed_sns",
        "status": "sent",
    }

    logger.info("Security alert stub-sent successfully")

    return alert_payload