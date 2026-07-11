import os
import json
import boto3
from dotenv import load_dotenv
from backend.app.logger import get_logger
from backend.app.models.alert import AlertDecision
from backend.app.models.risk_score import RiskScore
from backend.app.models.threat_event import ThreatEvent

load_dotenv()

logger = get_logger("sns_service")

REGION        = os.environ.get("AWS_REGION", "us-east-1")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN","")

sns = boto3.client("sns", region_name=REGION)


def send_security_alert(
   event: ThreatEvent,
   risk: RiskScore,
   decision: AlertDecision,
) -> dict:
    """Send a real security alert to SNS topic."""

    subject = f"CloudGuard AI Alert: {risk.severity.upper()} risk detected"

    message = json.dumps({
        "event_type":         event.event_type,
        "source_ip":          event.source_ip,
        "actor":              event.actor,
        "risk_score":         risk.score,
        "severity":           risk.severity,
        "reasons":            risk.reasons,
        "recommended_action": decision.action,
    }, indent=2)
    
    try: 
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
        )
        logger.info(f"SNS alert sent, MessageId: {response['MessageId']}")
        return {
            "message_id": response["MessageId"],
            "delivery":   "sns",
            "status":     "sent",
        }
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")
        return {
            "error":     str(e),
            "delivery":  "sns",
            "status":    "failed",
        }