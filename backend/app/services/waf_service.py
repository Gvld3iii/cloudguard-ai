from backend.app.logger import get_logger

logger = get_logger("waf_service")


def block_ip_address(source_ip: str) -> dict:
    logger.info(f"Stub WAF block requested for source_ip={source_ip}")

    result = {
        "source_ip": source_ip,
        "action": "block_ip",
        "provider": "stubbed_waf",
        "status": "blocked",
    }

    logger.info(f"Stub WAF block completed for source_ip={source_ip}")

    return result