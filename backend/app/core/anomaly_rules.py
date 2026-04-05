from backend.app.models.threat_event import ThreatEvent


def evaluate_anomalies(event: ThreatEvent) -> list[str]:
    reasons = []

    if event.failed_logins >= 5:
        reasons.append("High number of failed login attempts")

    if event.api_calls_last_minute >= 100:
        reasons.append("Unusually high API call volume")

    if event.privileged_action:
        reasons.append("Privileged action detected")

    if event.region and event.region.lower() not in ["us-east-1", "us-west-2"]:
        reasons.append("Login or action from unusual region")

    return reasons