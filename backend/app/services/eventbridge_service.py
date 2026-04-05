from backend.app.logger import get_logger

logger = get_logger("eventbridge_service")


def publish_event(event_payload: dict) -> dict:
    logger.info("Stub EventBridge publish requested")

    result = {
        "provider": "stubbed_eventbridge",
        "status": "published",
        "event_payload": event_payload,
    }

    logger.info("Stub EventBridge publish completed")

    return result