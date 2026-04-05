from backend.app.logger import get_logger

logger = get_logger("cloudtrail_service")


def fetch_recent_events() -> dict:
    logger.info("Stub CloudTrail fetch requested")

    result = {
        "provider": "stubbed_cloudtrail",
        "status": "ok",
        "events": [],
        "message": "CloudTrail integration not yet implemented",
    }

    logger.info("Stub CloudTrail fetch completed")

    return result