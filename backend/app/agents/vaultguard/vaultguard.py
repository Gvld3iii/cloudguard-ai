"""
VaultGuard — Secrets & Credential Protection Agent
Scans text, logs, code, and env files for exposed credentials,
API keys, tokens, and hardcoded secrets.
"""

import re
from core.models import VaultGuardPayload, ThreatEvent, AgentName, Severity
from typing import List

AGENT = AgentName.VAULTGUARD

# ── Secret detection patterns ─────────────────────────────────────────────────
PATTERNS = [
    {
        "rule":        "AWS_ACCESS_KEY",
        "pattern":     r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID exposed",
        "severity":    Severity.CRITICAL,
        "risk":        98.0,
        "action":      "rotate_key_immediate",
    },
    {
        "rule":        "AWS_SECRET_KEY",
        "pattern":     r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]",
        "description": "AWS Secret Access Key exposed",
        "severity":    Severity.CRITICAL,
        "risk":        99.0,
        "action":      "rotate_key_immediate",
    },
    {
        "rule":        "GITHUB_TOKEN",
        "pattern":     r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
        "description": "GitHub Personal Access Token exposed",
        "severity":    Severity.CRITICAL,
        "risk":        95.0,
        "action":      "revoke_token_immediate",
    },
    {
        "rule":        "OPENAI_API_KEY",
        "pattern":     r"sk-[A-Za-z0-9]{48}",
        "description": "OpenAI API Key exposed",
        "severity":    Severity.HIGH,
        "risk":        88.0,
        "action":      "revoke_token",
    },
    {
        "rule":        "STRIPE_KEY",
        "pattern":     r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
        "description": "Stripe API key exposed",
        "severity":    Severity.CRITICAL,
        "risk":        97.0,
        "action":      "revoke_token_immediate",
    },
    {
        "rule":        "PRIVATE_KEY",
        "pattern":     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "description": "Private key material exposed",
        "severity":    Severity.CRITICAL,
        "risk":        100.0,
        "action":      "rotate_key_immediate",
    },
    {
        "rule":        "HARDCODED_PASSWORD",
        "pattern":     r"(?i)(?:password|passwd|pwd)\s*=\s*['\"]([^'\"]{6,})['\"]",
        "description": "Hardcoded password found in content",
        "severity":    Severity.HIGH,
        "risk":        82.0,
        "action":      "alert_and_rotate",
    },
    {
        "rule":        "DATABASE_URL_WITH_CREDS",
        "pattern":     r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@",
        "description": "Database connection string with embedded credentials",
        "severity":    Severity.CRITICAL,
        "risk":        96.0,
        "action":      "rotate_key_immediate",
    },
    {
        "rule":        "SLACK_TOKEN",
        "pattern":     r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        "description": "Slack token exposed",
        "severity":    Severity.HIGH,
        "risk":        85.0,
        "action":      "revoke_token",
    },
    {
        "rule":        "GENERIC_SECRET",
        "pattern":     r"(?i)(?:secret|api_key|apikey|access_token|auth_token)\s*=\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        "description": "Generic secret or API key pattern found",
        "severity":    Severity.MEDIUM,
        "risk":        60.0,
        "action":      "review_and_rotate",
    },
    {
        "rule":        "JWT_TOKEN",
        "pattern":     r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "description": "JWT token found in content — may expose session",
        "severity":    Severity.MEDIUM,
        "risk":        55.0,
        "action":      "invalidate_session",
    },
    {
        "rule":        "SSH_KEY_IN_CODE",
        "pattern":     r"ssh-rsa AAAA[A-Za-z0-9+/]{100,}",
        "description": "SSH public key embedded in code/logs",
        "severity":    Severity.LOW,
        "risk":        25.0,
        "action":      "review",
    },
]


def analyze(payload: VaultGuardPayload) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    content = payload.content

    for spec in PATTERNS:
        matches = re.findall(spec["pattern"], content)
        if matches:
            # Redact the match for safe logging
            safe_match = str(matches[0])[:8] + "***" if matches else "***"
            events.append(ThreatEvent(
                agent       = AGENT,
                rule        = spec["rule"],
                description = f"{spec['description']} in {payload.source}",
                severity    = spec["severity"],
                risk_score  = spec["risk"],
                action      = spec["action"],
                metadata    = {
                    "source":       payload.source,
                    "match_count":  len(matches),
                    "redacted":     safe_match,
                },
            ))

    return events
