import os 
import boto3
from dotenv import load_dotenv
from backend.app.logger import get_logger

load_dotenv()

logger = get_logger("waf_service")

REGION       = os.environ.get("AWS_REGION", "us-east-1")
IP_SET_ID    = os.environ.get("WAF_IP_SET_ID", "")
IP_SET_NAME  = os.environ.get("WAF_IP_SET_NAME", "cloudguard-blocked-ips")
IP_SET_SCOPE = os.environ.get("WAF_IP_SET_SCOPE", "REGIONAL")

waf = boto3.client("wafv2", region_name=REGION)

def block_ip_address(source_ip: str) -> dict:
    """Block an Ip address in AWS WAF IP set."""

    try:
        token_response = waf.get_ip_set(
            Name=IP_SET_NAME,
            Scope=IP_SET_SCOPE,
            Id=IP_SET_ID,
        )
        lock_token    = token_response["LockToken"]
        existing_ips  = token_response["IPSet"]["Addresses"]

        cidr = f"{source_ip}/32"

        if cidr in existing_ips:
            logger.info(f"IP {source_ip} already blocked in waf")
            return {
                "source_ip": source_ip,
                "action":    "already_blocked",
                "provider":  "wafv2",
                "status":    "skipped",
            }
        updated_ips = existing_ips + [cidr]

        waf.update_ip_set(
            Name=IP_SET_NAME,
            Scope=IP_SET_SCOPE,
            Id=IP_SET_ID,
            LockToken=lock_token,
            Addresses=updated_ips,
        )

        logger.info(f"IP {source_ip} blocked in WAF successfully")
        return {
            "source_ip": source_ip,
            "action":    "block_ip",
            "provider":  "wafv2",
            "status":    "blocked",
        }
    
    except Exception as e:
        logger.error(f"WAF block failed for {source_ip}: {e}")
        return {
            "source_ip":  source_ip,
            "error":      str(e),
            "provider":   "wafv2",
            "status":     "failed",
        }