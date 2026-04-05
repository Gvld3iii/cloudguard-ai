from backend.app.config import settings
from backend.app.logger import get_logger
from backend.app.models.alert import AlertDecision
from backend.app.models.risk_score import RiskScore

logger = get_logger("response_engine")


def decide_response(risk: RiskScore) -> AlertDecision:
    logger.info(
        f"Evaluating response for risk score={risk.score}, severity={risk.severity}"
    )

    if risk.score >= settings.RISK_BLOCK_THRESHOLD:
        decision = AlertDecision(
            action="block_ip",
            message="Risk score exceeded block threshold. Recommend blocking source IP.",
        )
    elif risk.score >= settings.RISK_ALERT_THRESHOLD:
        decision = AlertDecision(
            action="send_alert",
            message="Risk score exceeded alert threshold. Recommend sending security alert.",
        )
    else:
        decision = AlertDecision(
            action="log_only",
            message="Risk score below action thresholds. Log event for review.",
        )

    logger.info(
        f"Response decision made: action={decision.action}, message={decision.message}"
    )

    return decision