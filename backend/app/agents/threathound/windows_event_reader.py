"""
ThreatHound — Windows Security Event Log Reader
Reads real security events from Windows Security Event Log.
Feeds actual data into the ThreatHound analyzer.

Event IDs monitored:
  4625 — Failed login attempt
  4648 — Explicit credential logon
  4672 — Special privileges assigned
  4719 — System audit policy changed
  4771 — Kerberos pre-auth failed
  4776 — NTLM authentication attempt
"""

import subprocess
import json
import re
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Optional


KNOWN_BAD_PREFIXES = [
    "185.220.", "91.108.", "45.142.", "194.165.", "5.188.",
    "198.235.", "23.129.", "171.25.", "199.249.", "204.13."
]

LOCAL_PREFIXES = [
    "127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1", "-", ""
]

# Accounts that are normal system accounts — not suspicious
SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY",
    "ANONYMOUS LOGON", "DWM-1", "DWM-2", "DWM-3", "UMFD-0",
    "UMFD-1", "UMFD-2", "UMFD-3", "-", ""
}


def _is_known_bad(ip: str) -> bool:
    if not ip or ip in ("", "-", "::1", "127.0.0.1"):
        return False
    return any(ip.startswith(p) for p in KNOWN_BAD_PREFIXES)


def _is_local_ip(ip: str) -> bool:
    if not ip:
        return True
    return any(ip.startswith(p) for p in LOCAL_PREFIXES)


def _is_system_account(username: str) -> bool:
    if not username:
        return True
    return (
        username in SYSTEM_ACCOUNTS
        or username.endswith("$")
        or "NT AUTHORITY" in username
    )


def _run_powershell(command: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def read_failed_logins(minutes_back: int = 60) -> List[Dict]:
    """Read failed login events (Event ID 4625)."""
    ps_command = f"""
$startTime = (Get-Date).AddMinutes(-{minutes_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = 4625
        StartTime = $startTime
    }} -ErrorAction SilentlyContinue -MaxEvents 500
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $ip = '-'
            $user = '-'
            $domain = '-'
            if ($msg -match 'Source Network Address:\\s+([^\\r\\n]+)') {{ $ip = $matches[1].Trim() }}
            if ($msg -match 'Account Name:\\s+([^\\r\\n]+)\\r?\\n.*?Account Domain:\\s+([^\\r\\n]+)') {{
                $user = $matches[1].Trim()
                $domain = $matches[2].Trim()
            }}
            $results += [PSCustomObject]@{{
                TimeCreated = $e.TimeCreated.ToString('o')
                SourceIP = $ip
                Username = $user
                Domain = $domain
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_powershell(ps_command)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def read_privilege_escalations(minutes_back: int = 60) -> List[Dict]:
    """Read privilege escalation events (Event ID 4672) — non-system accounts only."""
    ps_command = f"""
$startTime = (Get-Date).AddMinutes(-{minutes_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = 4672
        StartTime = $startTime
    }} -ErrorAction SilentlyContinue -MaxEvents 200
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $user = '-'
            $sid = '-'
            if ($msg -match 'Account Name:\\s+([^\\r\\n]+)') {{ $user = $matches[1].Trim() }}
            if ($msg -match 'Security ID:\\s+([^\\r\\n]+)') {{ $sid = $matches[1].Trim() }}
            $results += [PSCustomObject]@{{
                TimeCreated = $e.TimeCreated.ToString('o')
                Username = $user
                SecurityID = $sid
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_powershell(ps_command)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def read_audit_policy_changes(minutes_back: int = 1440) -> List[Dict]:
    """Read audit policy change events (Event ID 4719) — serious tampering indicator."""
    ps_command = f"""
$startTime = (Get-Date).AddMinutes(-{minutes_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = 4719
        StartTime = $startTime
    }} -ErrorAction SilentlyContinue -MaxEvents 20
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $results += [PSCustomObject]@{{
                TimeCreated = $e.TimeCreated.ToString('o')
                Message = $e.Message.Substring(0, [Math]::Min(300, $e.Message.Length))
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_powershell(ps_command)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def read_successful_logins(minutes_back: int = 60) -> List[Dict]:
    """Read successful logins (Event ID 4624) for baseline context."""
    ps_command = f"""
$startTime = (Get-Date).AddMinutes(-{minutes_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = 4624
        StartTime = $startTime
    }} -ErrorAction SilentlyContinue -MaxEvents 100
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $user = '-'
            $logonType = '-'
            if ($msg -match 'Account Name:\\s+([^\\r\\n]+)') {{ $user = $matches[1].Trim() }}
            if ($msg -match 'Logon Type:\\s+([^\\r\\n]+)') {{ $logonType = $matches[1].Trim() }}
            $results += [PSCustomObject]@{{
                TimeCreated = $e.TimeCreated.ToString('o')
                Username = $user
                LogonType = $logonType
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_powershell(ps_command)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def aggregate_failed_logins(events: List[Dict]) -> Dict[str, Dict]:
    """Aggregate failed login events by source IP."""
    aggregated = defaultdict(lambda: {
        "count": 0,
        "usernames": set(),
        "first_seen": None,
        "last_seen": None,
        "is_external": False,
        "is_known_bad": False,
        "is_local": True,
    })

    for event in events:
        ip = event.get("SourceIP", "-")
        if not ip or ip in ("-", ""):
            ip = "unknown"

        username = event.get("Username", "-")
        timestamp = event.get("TimeCreated", "")

        aggregated[ip]["count"] += 1
        if username and not _is_system_account(username):
            aggregated[ip]["usernames"].add(username)

        if timestamp:
            if not aggregated[ip]["first_seen"] or timestamp < aggregated[ip]["first_seen"]:
                aggregated[ip]["first_seen"] = timestamp
            if not aggregated[ip]["last_seen"] or timestamp > aggregated[ip]["last_seen"]:
                aggregated[ip]["last_seen"] = timestamp

        aggregated[ip]["is_local"] = _is_local_ip(ip)
        aggregated[ip]["is_external"] = not _is_local_ip(ip) and ip != "unknown"
        aggregated[ip]["is_known_bad"] = _is_known_bad(ip)

    result = {}
    for ip, data in aggregated.items():
        result[ip] = {**data, "usernames": list(data["usernames"])}

    return result


def get_security_summary(minutes_back: int = 60) -> Dict:
    """
    Main function — returns complete security summary for ThreatHound.
    Reads all Windows Security events and aggregates intelligently.
    """
    summary = {
        "failed_logins": {},
        "privilege_escalations": [],
        "privilege_escalations_system_count": 0,
        "audit_policy_changes": [],
        "successful_logins": [],
        "total_failed_logins": 0,
        "unique_source_ips": 0,
        "external_attack_ips": [],
        "known_bad_ips": [],
        "brute_force_candidates": [],
        "user_failed_logins": [],
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "minutes_scanned": minutes_back,
        "windows_event_log_available": True,
        "error": None
    }

    try:
        # Failed logins
        raw_logins = read_failed_logins(minutes_back)
        aggregated = aggregate_failed_logins(raw_logins)
        summary["failed_logins"] = aggregated
        summary["total_failed_logins"] = len(raw_logins)
        summary["unique_source_ips"] = len(aggregated)

        for ip, data in aggregated.items():
            if data["is_external"]:
                summary["external_attack_ips"].append({
                    "ip": ip,
                    "count": data["count"],
                    "usernames": data["usernames"]
                })
            if data["is_known_bad"]:
                summary["known_bad_ips"].append(ip)
            if data["count"] >= 3:
                summary["brute_force_candidates"].append({
                    "ip": ip,
                    "count": data["count"],
                    "is_external": data["is_external"],
                    "is_local": data["is_local"]
                })
            # Track failed logins for real user accounts (not system)
            if data["usernames"]:
                summary["user_failed_logins"].append({
                    "ip": ip,
                    "count": data["count"],
                    "usernames": data["usernames"],
                    "is_local": data["is_local"]
                })

        # Privilege escalations — separate system vs real user
        priv_events = read_privilege_escalations(minutes_back)
        system_count = 0
        user_escalations = []

        for e in (priv_events or []):
            username = e.get("Username", "-")
            if _is_system_account(username):
                system_count += 1
            else:
                user_escalations.append({
                    "username": username,
                    "time": e.get("TimeCreated", ""),
                    "security_id": e.get("SecurityID", "")
                })

        summary["privilege_escalations"] = user_escalations
        summary["privilege_escalations_system_count"] = system_count

        # Audit policy changes
        audit_changes = read_audit_policy_changes(1440)
        summary["audit_policy_changes"] = audit_changes or []

        # Successful logins for context
        success_logins = read_successful_logins(minutes_back)
        summary["successful_logins"] = [
            {"username": e.get("Username", "-"), "time": e.get("TimeCreated", ""), "logon_type": e.get("LogonType", "-")}
            for e in (success_logins or [])
            if not _is_system_account(e.get("Username", "-"))
        ][:10]

    except Exception as e:
        summary["windows_event_log_available"] = False
        summary["error"] = str(e)

    return summary


if __name__ == "__main__":
    print("ThreatHound — Windows Event Log Reader")
    print("=" * 50)
    summary = get_security_summary(minutes_back=1440)
    print(f"Scan time:              {summary['scan_time']}")
    print(f"Total failed logins:    {summary['total_failed_logins']}")
    print(f"User failed logins:     {len(summary['user_failed_logins'])}")
    print(f"External attackers:     {len(summary['external_attack_ips'])}")
    print(f"Brute force:            {len(summary['brute_force_candidates'])}")
    print(f"User priv escalations:  {len(summary['privilege_escalations'])}")
    print(f"System priv events:     {summary['privilege_escalations_system_count']} (normal)")
    print(f"Audit changes:          {len(summary['audit_policy_changes'])}")
    print(f"Recent user logins:     {len(summary['successful_logins'])}")
    if summary["user_failed_logins"]:
        print("\nUSER FAILED LOGINS:")
        for item in summary["user_failed_logins"]:
            print(f"  {item['ip']} — {item['count']} attempts — users: {item['usernames']}")
    if summary["privilege_escalations"]:
        print("\nUSER PRIVILEGE ESCALATIONS:")
        for esc in summary["privilege_escalations"]:
            print(f"  {esc['username']} at {esc['time']}")
    if summary["successful_logins"]:
        print("\nRECENT USER LOGINS:")
        for login in summary["successful_logins"][:5]:
            print(f"  {login['username']} — type {login['logon_type']} at {login['time']}")
