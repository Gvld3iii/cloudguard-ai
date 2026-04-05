from datetime import datetime, timezone

from backend.app.logger import get_logger

logger = get_logger("timestamps")


def utc_now_iso() -> str:
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"Generated UTC timestamp: {timestamp}")
    return timestamp