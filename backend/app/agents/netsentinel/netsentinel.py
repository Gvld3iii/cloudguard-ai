"""
NetSentinel — Network Traffic Analysis Agent
Analyzes network connections for C2 beaconing, DNS tunneling,
data exfiltration, lateral movement, and suspicious traffic patterns.
"""

from core.models import NetSentinelPayload, ThreatEvent, AgentName, Severity
from typing import List
import re

AGENT = AgentName.NETSENTINEL

# Ports commonly used for C2 / malware comms
C2_PORTS      = {4444, 4445, 1234, 31337, 8080, 8443, 6667, 6666, 9001, 9030}
# Internal RFC1918 ranges
INTERNAL_NETS = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                 "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                 "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]
# Suspicious TLDs often used in malware / phishing
SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top"]
# DNS tunneling patterns — encoded payloads in subdomains
DNS_TUNNEL_RE = re.compile(r"([a-f0-9]{32,}|[A-Za-z0-9+/]{40,}==?)\..*")


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in INTERNAL_NETS)


def _is_c2_port(port: int) -> bool:
    return port in C2_PORTS


def _suspicious_tld(query: str) -> bool:
    return any(query.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _dns_tunneling(query: str) -> bool:
    return bool(DNS_TUNNEL_RE.match(query))


def analyze(payload: NetSentinelPayload) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    src = payload.source_ip
    dst = payload.dest_ip

    # ── Rule 1: C2 Beaconing Port ─────────────────────────────────────────────
    if _is_c2_port(payload.dest_port):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "C2_BEACON_PORT",
            description = f"Connection to known C2 port {payload.dest_port} from {src} → {dst}",
            severity    = Severity.CRITICAL,
            risk_score  = 92.0,
            action      = "block_connection",
            metadata    = {
                "source_ip": src, "dest_ip": dst,
                "dest_port": payload.dest_port, "protocol": payload.protocol,
            },
        ))

    # ── Rule 2: Data Exfiltration (large outbound) ────────────────────────────
    if payload.bytes_sent > 100_000_000 and not _is_internal(dst):  # 100MB+
        risk = min(100, 50 + payload.bytes_sent / 10_000_000)
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "DATA_EXFILTRATION",
            description = f"Large outbound transfer {payload.bytes_sent // 1_000_000}MB from {src} to external {dst}",
            severity    = Severity.CRITICAL,
            risk_score  = round(risk, 1),
            action      = "block_connection",
            metadata    = {
                "source_ip":   src, "dest_ip": dst,
                "bytes_sent":  payload.bytes_sent,
                "bytes_recv":  payload.bytes_received,
            },
        ))

    # ── Rule 3: Lateral Movement ──────────────────────────────────────────────
    if _is_internal(src) and _is_internal(dst) and payload.dest_port in {445, 135, 5985, 5986, 22, 3389}:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "LATERAL_MOVEMENT",
            description = f"Potential lateral movement: {src} → {dst}:{payload.dest_port} (internal admin protocol)",
            severity    = Severity.HIGH,
            risk_score  = 78.0,
            action      = "alert_and_monitor",
            metadata    = {
                "source_ip": src, "dest_ip": dst,
                "dest_port": payload.dest_port,
            },
        ))

    # ── Rule 4: DNS Tunneling ─────────────────────────────────────────────────
    if payload.dns_query:
        if _dns_tunneling(payload.dns_query):
            events.append(ThreatEvent(
                agent       = AGENT,
                rule        = "DNS_TUNNELING",
                description = f"DNS tunneling detected — encoded payload in query: {payload.dns_query[:40]}...",
                severity    = Severity.CRITICAL,
                risk_score  = 93.0,
                action      = "block_dns_query",
                metadata    = {"dns_query": payload.dns_query[:80], "source_ip": src},
            ))
        elif _suspicious_tld(payload.dns_query):
            events.append(ThreatEvent(
                agent       = AGENT,
                rule        = "SUSPICIOUS_DNS_TLD",
                description = f"DNS query to suspicious TLD: {payload.dns_query}",
                severity    = Severity.MEDIUM,
                risk_score  = 58.0,
                action      = "alert",
                metadata    = {"dns_query": payload.dns_query, "source_ip": src},
            ))

    # ── Rule 5: Beaconing Pattern (regular short bursts) ─────────────────────
    if (payload.connection_duration_sec < 5.0 and
        payload.packet_count > 50 and
        payload.bytes_sent < 1000 and
        not _is_internal(dst)):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "BEACONING_PATTERN",
            description = f"Beaconing pattern detected: {src} → {dst} — regular small packets to external host",
            severity    = Severity.HIGH,
            risk_score  = 82.0,
            action      = "block_connection",
            metadata    = {
                "source_ip":     src, "dest_ip": dst,
                "packet_count":  payload.packet_count,
                "bytes_sent":    payload.bytes_sent,
                "duration_sec":  payload.connection_duration_sec,
            },
        ))

    # ── Rule 6: Tor Exit Node / Unusual Port ─────────────────────────────────
    if payload.dest_port in {9001, 9030, 9050, 9051}:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "TOR_NETWORK_DETECTED",
            description = f"Connection to Tor network port {payload.dest_port} from {src}",
            severity    = Severity.HIGH,
            risk_score  = 75.0,
            action      = "alert_and_monitor",
            metadata    = {"source_ip": src, "dest_port": payload.dest_port},
        ))

    return events
