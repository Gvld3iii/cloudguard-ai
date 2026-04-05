import ipaddress

from backend.app.logger import get_logger

logger = get_logger("validators")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        logger.warning(f"Invalid IP address detected: {value}")
        return False


def validate_required_fields(payload: dict, required_fields: list[str]) -> list[str]:
    missing_fields = [field for field in required_fields if field not in payload]

    if missing_fields:
        logger.warning(f"Missing required fields: {missing_fields}")

    return missing_fields