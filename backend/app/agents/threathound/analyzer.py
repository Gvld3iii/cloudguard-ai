"""
ThreatHound — Intrusion Detection Agent
Monitors login attempts, port scans, brute force attacks,
and geo-anomalous access patterns.
"""

from core.models import ThreatHoundPayload, ThreatEvent, AgentName, Severity
from typing import List

AGENT = AgentName.THREATHOUND

# Known bad IP ranges (simplified — real impl would hit threat intel feeds)
KNOWN_BAD_PREFIXES = ["185.220.", "91.108.", "45.142.", "194.165.", "5.188."]

# Ports that are almost never legitimately scanned
SENSITIVE_PORTS = {22, 23, 3389, 5900, 1433, 3306, 6379, 27017, 9200}


def _is_known_bad(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in KNOWN_BAD_PREFIXES)


def analyze(payload: ThreatHoundPayload) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []

    # ── Rule 1: Brute Force Detection ────────────────────────────────────────
    if payload.failed_attempts >= 10:
        severity  = Severity.CRITICAL if payload.failed_attempts >= 50 else Severity.HIGH
        risk      = min(100, 40 + payload.failed_attempts * 1.2)
        action    = "block_ip" if payload.failed_attempts >= 50 else "rate_limit"
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "BRUTE_FORCE_DETECTED",
            description = f"Brute force attack from {payload.source_ip} — {payload.failed_attempts} failed attempts",
            severity    = severity,
            risk_score  = round(risk, 1),
            action      = action,
            metadata    = {
                "source_ip":       payload.source_ip,
                "failed_attempts": payload.failed_attempts,
                "event_type":      payload.event_type,
            },
        ))

    # ── Rule 2: Port Scanning ─────────────────────────────────────────────────
    if payload.ports_scanned >= 20:
        severity = Severity.CRITICAL if payload.ports_scanned >= 100 else Severity.HIGH
        risk     = min(100, 30 + payload.ports_scanned * 0.7)
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "PORT_SCAN_DETECTED",
            description = f"Port scan from {payload.source_ip} — {payload.ports_scanned} ports probed",
            severity    = severity,
            risk_score  = round(risk, 1),
            action      = "block_ip",
            metadata    = {
                "source_ip":     payload.source_ip,
                "ports_scanned": payload.ports_scanned,
            },
        ))

    # ── Rule 3: Known Bad IP ──────────────────────────────────────────────────
    if payload.known_bad_ip or _is_known_bad(payload.source_ip):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "KNOWN_MALICIOUS_IP",
            description = f"Traffic from known malicious IP {payload.source_ip}",
            severity    = Severity.CRITICAL,
            risk_score  = 95.0,
            action      = "block_ip_immediate",
            metadata    = {"source_ip": payload.source_ip},
        ))

    # ── Rule 4: Geo Anomaly ───────────────────────────────────────────────────
    if payload.geo_anomaly:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "GEO_ANOMALY_DETECTED",
            description = f"Login from {payload.source_ip} — geographic anomaly (unusual country/region)",
            severity    = Severity.MEDIUM,
            risk_score  = 55.0,
            action      = "require_mfa",
            metadata    = {"source_ip": payload.source_ip, "event_type": payload.event_type},
        ))

    # ── Rule 5: High Request Rate ─────────────────────────────────────────────
    if payload.requests_per_minute >= 500:
        severity = Severity.CRITICAL if payload.requests_per_minute >= 2000 else Severity.HIGH
        risk     = min(100, 35 + payload.requests_per_minute * 0.03)
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "DDoS_PATTERN_DETECTED",
            description = f"DDoS pattern from {payload.source_ip} — {payload.requests_per_minute} req/min",
            severity    = severity,
            risk_score  = round(risk, 1),
            action      = "rate_limit_aggressive",
            metadata    = {
                "source_ip":            payload.source_ip,
                "requests_per_minute":  payload.requests_per_minute,
            },
        ))

    # ── Rule 6: Credential Stuffing ───────────────────────────────────────────
    if payload.event_type in ("login_attempt", "ssh_bruteforce") and payload.failed_attempts >= 5 and payload.requests_per_minute >= 100:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "CREDENTIAL_STUFFING",
            description = f"Credential stuffing from {payload.source_ip} — high-volume automated login attempts",
            severity    = Severity.HIGH,
            risk_score  = 80.0,
            action      = "block_ip",
            metadata    = {
                "source_ip":            payload.source_ip,
                "failed_attempts":      payload.failed_attempts,
                "requests_per_minute":  payload.requests_per_minute,
            },
        ))

    return events