"""
Sentinel AI — Shared Models
Central data structures used by all 5 agents.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class AgentName(str, Enum):
    THREATHOUND  = "ThreatHound"
    VAULTGUARD   = "VaultGuard"
    NETSENTINEL  = "NetSentinel"
    PHAGEKILLER  = "PhageKiller"
    AUDITMIND    = "AuditMind"


class ThreatEvent(BaseModel):
    agent:       AgentName
    rule:        str
    description: str
    severity:    Severity
    risk_score:  float = Field(ge=0, le=100)
    action:      str
    metadata:    dict  = {}
    timestamp:   str   = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SentinelReport(BaseModel):
    total_events:    int
    critical_count:  int
    high_count:      int
    medium_count:    int
    low_count:       int
    peak_risk:       float
    agents_active:   List[str]
    events:          List[ThreatEvent]
    generated_at:    str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Inbound payloads per agent ────────────────────────────────────────────────

class ThreatHoundPayload(BaseModel):
    source_ip:            str
    target_ip:            Optional[str] = None
    event_type:           str  # login_attempt, port_scan, ssh_bruteforce, etc.
    failed_attempts:      int  = 0
    ports_scanned:        int  = 0
    requests_per_minute:  int  = 0
    geo_anomaly:          bool = False
    known_bad_ip:         bool = False

class VaultGuardPayload(BaseModel):
    content:       str   # raw text, log line, code snippet, env file
    source:        str   # filename, log path, etc.
    scan_depth:    str   = "full"  # full | quick

class NetSentinelPayload(BaseModel):
    source_ip:        str
    dest_ip:          str
    dest_port:        int
    protocol:         str  = "tcp"
    bytes_sent:       int  = 0
    bytes_received:   int  = 0
    dns_query:        Optional[str] = None
    packet_count:     int  = 0
    connection_duration_sec: float = 0.0

class PhageKillerPayload(BaseModel):
    process_name:     str
    pid:              int
    cpu_percent:      float = 0.0
    memory_mb:        float = 0.0
    parent_process:   Optional[str] = None
    file_path:        Optional[str] = None
    network_connections: int = 0
    file_ops_per_sec: int   = 0
    spawned_children: int   = 0

class AuditMindPayload(BaseModel):
    log_line:     str
    log_source:   str   # syslog, auth.log, windows_event, cloudtrail
    username:     Optional[str] = None
    action:       Optional[str] = None
    resource:     Optional[str] = None