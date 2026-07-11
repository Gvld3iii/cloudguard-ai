import os
import boto3 
from datetime import datetime, timezone
from dotenv import load_dotenv
from backend.app.logger import get_logger
from backend.app.models.risk_score import RiskScore
from backend.app.models.threat_event import ThreatEvent

load_dotenv()

logger = get_logger("dynamodb_service")

TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "cloudguard-threat-events")
REGION     = os.environ.get("AWS_REGION", "us-east-1")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
table    = dynamodb.Table(TABLE_NAME)


def save_threat_event(event: ThreatEvent, risk: RiskScore) -> dict:
    """save a real threat event to DynamoDB."""

    timestamp = datetime.now(timezone.utc).isoformat()

    item = {
        "event_id":              f"{event.source_ip}_{timestamp}",
        "timestamp":             timestamp,
        "event_type":            event.event_type,
        "source_ip":             event.source_ip,
        "actor":                 event.actor,
        "region":                event.region,
        "login_time":            event.login_time,
        "api_calls_last_minute": event.api_calls_last_minute,
        "failed_logins":         event.failed_logins,
        "privileged_action":     event.privileged_action,
        "risk_score":            str(risk.score),
        "severity":              risk.severity,
        "reasons":               risk.reasons,
        "storage":               "dynamodb",
        "status":                "saved",

    }

    try: 
        table.put_item(Item=item)
        logger.info(f"Threat Event saved to DynamoDB: {item['event_id']}")
        return item
    
    except Exception as e:
        logger.error(f"DynamoDB save failed: {e}")
        return {
            "error":   str(e),
            "storage": "dynamodb",
            "status":  "failed",
        }
        
