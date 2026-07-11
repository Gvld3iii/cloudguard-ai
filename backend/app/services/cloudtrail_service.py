import os 
import boto3 
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from backend.app.logger import get_logger

load_dotenv()

logger = get_logger("cloudtrail_service")

REGION = os.environ.get("AWS_REGION", "us-east-1")

cloudtrail = boto3.client("cloudtrail", region_name=REGION)

def fetch_recent_events(minutes: int = 15) -> dict:
    """Fetch real CloudTrail events from the last minutes."""
    
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes)

    try: 
        response = cloudtrail.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50,
        )

        events = []
        for record in response.get("Events", []):
            events.append({
                "event_id":   record.get("EventId"),
                "event_name": record.get("EventName"),
                "event_time": record.get("EventTime").isoformat(),
                "username":   record.get("Username"),
                "source_ip":  record.get("SourceIPAddress"),
                "resources":   record.get("Resources", []),
            })

        logger.info(f"Fetched {len(events)} CloudTrail events")
        return {
            "provider": "cloudtrail",
            "status":   "ok",
            "events":   events,
            "count":    len(events),
        }
    except Exception as e:
        logger.error(f"Cloudtrail fetch failed: {e}")
        return {
            "provider": "cloudtrail",
            "status":   "failed",
            "events":   [],
            "error":    str(e),
        }
        