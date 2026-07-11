"""
AuditMind — Compliance & Log Intelligence Agent
Parses system logs, auth logs, CloudTrail, and Windows events
to detect privilege escalation, suspicious sudo, account manipulation,
and audit trail tampering.
"""

import re
from core.models import AuditMindPayload, ThreatEvent, AgentName, Severity
from typing import List

AGENT = AgentName.AUDITMIND

# Privilege escalation commands
PRIV_ESC_PATTERNS = [
    r"sudo\s+su",
    r"sudo\s+-i",
    r"sudo\s+bash",
    r"chmod\s+[0-9]*7[0-9]*\s+/etc/passwd",
    r"chown\s+root",
    r"usermod\s+-aG\s+sudo",
    r"visudo",
    r"pkexec",
    r"setuid",
]

# Log tampering / covering tracks
TAMPERING_PATTERNS = [
    r">\s+/var/log",
    r"rm\s+-[rf]+\s+.*log",
    r"truncate\s+.*log",
    r"shred\s+.*log",
    r"history\s+-[cw]",
    r"unset\s+HISTFILE",
    r"export\s+HISTSIZE=0",
    r"auditctl\s+-e\s+0",
]

# Suspicious account manipulation
ACCOUNT_MANIP_PATTERNS = [
    r"useradd",
    r"adduser",
    r"passwd\s+root",
    r"usermod.*root",
    r"groupadd.*sudo",
    r"net\s+user\s+.*\s+/add",
    r"net\s+localgroup\s+administrators.*\/add",
]

# Sensitive resource access
SENSITIVE_RESOURCES = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "SAM", "SYSTEM", "SECURITY",   # Windows registry hives
    ".ssh/authorized_keys", ".bash_history",
    "/root/.ssh", "/root/.aws/credentials",
]

# Suspicious CloudTrail actions
CLOUDTRAIL_ALERTS = {
    "DeleteTrail":          (Severity.CRITICAL, 98.0, "CloudTrail logging disabled — covering tracks"),
    "StopLogging":          (Severity.CRITICAL, 97.0, "CloudTrail stopped — audit evasion"),
    "DeleteLogGroup":       (Severity.HIGH,     88.0, "CloudWatch log group deleted"),
    "CreateAccessKey":      (Severity.HIGH,     75.0, "New IAM access key created"),
    "AttachUserPolicy":     (Severity.HIGH,     80.0, "IAM policy attached to user"),
    "PutUserPolicy":        (Severity.HIGH,     78.0, "Inline IAM policy added to user"),
    "CreateUser":           (Severity.MEDIUM,   60.0, "New IAM user created"),
    "AssumeRoleWithWebIdentity": (Severity.MEDIUM, 55.0, "Role assumed via web identity"),
    "ConsoleLoginFailure":  (Severity.MEDIUM,   50.0, "AWS console login failure"),
}


def _check_patterns(log: str, patterns: list) -> List[str]:
    return [p for p in patterns if re.search(p, log, re.IGNORECASE)]


def analyze(payload: AuditMindPayload) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    log  = payload.log_line
    src  = payload.log_source

    # ── Rule 1: Privilege Escalation ─────────────────────────────────────────
    matched = _check_patterns(log, PRIV_ESC_PATTERNS)
    if matched:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "PRIVILEGE_ESCALATION",
            description = f"Privilege escalation attempt in {src}: {log[:80]}",
            severity    = Severity.CRITICAL,
            risk_score  = 95.0,
            action      = "alert_soc",
            metadata    = {
                "log_source": src,
                "username":   payload.username,
                "matched":    matched,
            },
        ))

    # ── Rule 2: Log Tampering ─────────────────────────────────────────────────
    matched = _check_patterns(log, TAMPERING_PATTERNS)
    if matched:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "LOG_TAMPERING",
            description = f"Log tampering / cover tracks in {src}: {log[:80]}",
            severity    = Severity.CRITICAL,
            risk_score  = 97.0,
            action      = "alert_soc_immediate",
            metadata    = {
                "log_source": src,
                "username":   payload.username,
                "matched":    matched,
            },
        ))

    # ── Rule 3: Account Manipulation ─────────────────────────────────────────
    matched = _check_patterns(log, ACCOUNT_MANIP_PATTERNS)
    if matched:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "ACCOUNT_MANIPULATION",
            description = f"Account manipulation detected in {src}: {log[:80]}",
            severity    = Severity.HIGH,
            risk_score  = 85.0,
            action      = "alert_and_review",
            metadata    = {
                "log_source": src,
                "username":   payload.username,
                "matched":    matched,
            },
        ))

    # ── Rule 4: Sensitive Resource Access ────────────────────────────────────
    for res in SENSITIVE_RESOURCES:
        if res.lower() in log.lower():
            events.append(ThreatEvent(
                agent       = AGENT,
                rule        = "SENSITIVE_RESOURCE_ACCESS",
                description = f"Access to sensitive resource '{res}' by {payload.username or 'unknown'} in {src}",
                severity    = Severity.HIGH,
                risk_score  = 80.0,
                action      = "alert",
                metadata    = {
                    "resource":   res,
                    "log_source": src,
                    "username":   payload.username,
                },
            ))
            break

    # ── Rule 5: CloudTrail Events ─────────────────────────────────────────────
    if payload.action and payload.action in CLOUDTRAIL_ALERTS:
        sev, risk, desc = CLOUDTRAIL_ALERTS[payload.action]
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = f"CLOUDTRAIL_{payload.action.upper()}",
            description = f"{desc} — action by {payload.username or 'unknown'} on {payload.resource or 'unknown'}",
            severity    = sev,
            risk_score  = risk,
            action      = "alert_soc",
            metadata    = {
                "action":   payload.action,
                "username": payload.username,
                "resource": payload.resource,
            },
        ))

    # ── Rule 6: Multiple Auth Failures in Log ────────────────────────────────
    fail_count = len(re.findall(r"authentication failure|failed password|invalid user|logon failure",
                                log, re.IGNORECASE))
    if fail_count >= 3:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "AUTH_FAILURE_SPIKE",
            description = f"Multiple authentication failures ({fail_count}) detected in single log entry",
            severity    = Severity.HIGH,
            risk_score  = 72.0,
            action      = "alert",
            metadata    = {
                "log_source":  src,
                "fail_count":  fail_count,
                "username":    payload.username,
            },
        ))

    return events
