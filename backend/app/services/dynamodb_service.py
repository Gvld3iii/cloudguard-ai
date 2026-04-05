from backend.app.logger import get_logger
from backend.app.models.risk_score import RiskScore
from backend.app.models.threat_event import ThreatEvent

logger = get_logger("dynamodb_service")


def save_threat_event(event: ThreatEvent, risk: RiskScore) -> dict:
    logger.info(
        f"Stub save to DynamoDB for source_ip={event.source_ip}, score={risk.score}"
    )

    record = {
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "actor": event.actor,
        "region": event.region,
        "login_time": event.login_time,
        "api_calls_last_minute": event.api_calls_last_minute,
        "failed_logins": event.failed_logins,
        "privileged_action": event.privileged_action,
        "risk_score": risk.score,
        "severity": risk.severity,
        "reasons": risk.reasons,
        "storage": "stubbed_dynamodb",
        "status": "saved",
    }

    logger.info("Threat event stub-saved successfully")

    return record