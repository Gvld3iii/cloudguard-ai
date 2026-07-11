import os
import json
import boto3
from datetime import datetime, timezone
from dotenv import load_dotenv
from backend.app.logger import get_logger

load_dotenv()

logger = get_logger("eventbridge_service")

REGION    = os.environ.get("AWS_REGION", "us-east-1")
EVENT_BUS = os.environ.get("EVENTBRIDGE_BUS_NAME", "cloudguard-events")

events = boto3.client("events", region_name=REGION)


def publish_threat_event(source: str, detail_type: str, detail: dict) -> dict:
    """Publish a threat event to EventBridge."""

    entry = {
        "Source":       f"cloudguard.{source}",
        "DetailType":   detail_type,
        "Detail":       json.dumps(detail),
        "EventBusName": EVENT_BUS,
        "Time":         datetime.now(timezone.utc),
    }

    try:
        response = events.put_events(Entries=[entry])

        failed = response.get("FailedEntryCount", 0)
        if failed > 0:
            logger.error(f"EventBridge failed to publish {failed} entries")
            return {
                "provider": "eventbridge",
                "status":   "partial_failure",
                "failed":   failed,
            }

        event_id = response["Entries"][0].get("EventId")
        logger.info(f"EventBridge event published: {event_id}")
        return {
            "event_id": event_id,
            "provider": "eventbridge",
            "status":   "published",
        }

    except Exception as e:
        logger.error(f"EventBridge publish failed: {e}")
        return {
            "error":    str(e),
            "provider": "eventbridge",
            "status":   "failed",
        }