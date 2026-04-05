from backend.app.logger import get_logger
from backend.app.models.threat_event import ThreatEvent

logger = get_logger("normalizer")


def normalize_event(payload: dict) -> ThreatEvent:
    logger.info("Normalizing incoming event payload")

    event = ThreatEvent(
        event_type=payload.get("event_type", "unknown"),
        source_ip=payload.get("source_ip", "0.0.0.0"),
        actor=payload.get("actor"),
        region=payload.get("region"),
        login_time=payload.get("login_time"),
        api_calls_last_minute=payload.get("api_calls_last_minute", 0),
        failed_logins=payload.get("failed_logins", 0),
        privileged_action=payload.get("privileged_action", False),
    )

    logger.info(
        f"Normalized event: type={event.event_type}, source_ip={event.source_ip}, actor={event.actor}"
    )

    return event