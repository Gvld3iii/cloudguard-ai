from backend.app.logger import get_logger

logger = get_logger("helpers")


def clamp_score(score: int, minimum: int = 0, maximum: int = 100) -> int:
    clamped = max(minimum, min(score, maximum))
    logger.info(f"Clamped score from {score} to {clamped}")
    return clamped


def severity_from_score(score: int) -> str:
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    logger.info(f"Mapped score {score} to severity {severity}")
    return severity