from fastapi import APIRouter

from backend.app.core.normalizer import normalize_event
from backend.app.core.response_engine import decide_response
from backend.app.core.risk_engine import calculate_risk
from backend.app.logger import get_logger
from backend.app.services.dynamodb_service import save_threat_event
from backend.app.services.sns_service import send_security_alert
from backend.app.services.waf_service import block_ip_address

router = APIRouter(prefix="/simulate", tags=["simulation"])
logger = get_logger("routes_simulate")


@router.post("")
def simulate_event(payload: dict):
    logger.info("Received simulation payload")

    event = normalize_event(payload)
    risk = calculate_risk(event)
    decision = decide_response(risk)

    stored_record = save_threat_event(event, risk)

    alert_result = None
    waf_result = None

    if decision.action == "send_alert":
        alert_result = send_security_alert(event, risk, decision)

    if decision.action == "block_ip":
        alert_result = send_security_alert(event, risk, decision)
        waf_result = block_ip_address(event.source_ip)

    logger.info(
        f"Simulation complete for source_ip={event.source_ip} with action={decision.action}"
    )

    return {
        "event": event.model_dump(),
        "risk": risk.model_dump(),
        "decision": decision.model_dump(),
        "storage_result": stored_record,
        "alert_result": alert_result,
        "waf_result": waf_result,
    }