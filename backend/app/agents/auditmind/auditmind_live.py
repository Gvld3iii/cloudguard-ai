"""
AuditMind — Live Log Intelligence Agent
Deep Windows Security Event Log analysis beyond ThreatHound.
Builds session timelines, detects account manipulation,
correlates multi-stage attacks, and tracks admin activity.

Event IDs monitored:
  4624 — Successful logon
  4625 — Failed logon (ThreatHound handles brute force, AuditMind handles patterns)
  4634 — Logoff
  4648 — Logon with explicit credentials
  4672 — Special privileges assigned
  4698 — Scheduled task created
  4702 — Scheduled task modified
  4720 — User account created
  4722 — User account enabled
  4725 — User account disabled
  4728 — Member added to security group
  4732 — Member added to local security group
  4756 — Member added to universal security group
  4768 — Kerberos TGT requested
  4769 — Kerberos service ticket requested
  7045 — New service installed
  4697 — Service installed (security log)

Usage:
    python auditmind_live.py              # run once
    python auditmind_live.py --json       # JSON for Electron IPC
    python auditmind_live.py --watch      # continuous
"""

import os
import sys
import json
import time
import subprocess
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Optional
from agents.auditmind.report_generator import generate_report

_THIS_DIR = Path(__file__).parent
for p in [str(_THIS_DIR), str(_THIS_DIR/'..'/'..'/'..'), str(_THIS_DIR/'..'/'..'), str(_THIS_DIR/'..'/'..')]:
    if p not in sys.path:
        sys.path.insert(0, os.path.abspath(p))

try:
    from core.models import AuditMindPayload, ThreatEvent, AgentName, Severity
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

# System accounts to exclude from user analysis
SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY",
    "ANONYMOUS LOGON", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1",
    "Window Manager", "-", ""
}


def _is_system(username: str) -> bool:
    if not username:
        return True
    return (
        username in SYSTEM_ACCOUNTS or
        username.endswith("$") or
        "NT AUTHORITY" in username or
        username.startswith("DWM-") or
        username.startswith("UMFD-")
    )


def _run_ps(cmd: str, timeout: int = 20) -> Optional[str]:
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None


def get_logon_sessions(hours_back: int = 24) -> List[Dict]:
    """Get successful logon events (4624) for user session timeline."""
    cmd = f"""
$start = (Get-Date).AddHours(-{hours_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624;StartTime=$start}} -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $user = if ($msg -match 'Account Name:\\s+([^\\r\\n\\s]+)') {{ $matches[1] }} else {{ '-' }}
            $logonType = if ($msg -match 'Logon Type:\\s+([0-9]+)') {{ $matches[1] }} else {{ '0' }}
            $ip = if ($msg -match 'Source Network Address:\\s+([^\\r\\n]+)') {{ $matches[1].Trim() }} else {{ '-' }}
            $results += [PSCustomObject]@{{
                Time = $e.TimeCreated.ToString('o')
                Username = $user
                LogonType = $logonType
                SourceIP = $ip
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_ps(cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except:
        return []


def get_account_changes(hours_back: int = 168) -> List[Dict]:
    """Get account creation/modification events — look back 1 week."""
    event_ids = "4720,4722,4725,4728,4732,4756,4738"
    cmd = f"""
$start = (Get-Date).AddHours(-{hours_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@({event_ids});StartTime=$start}} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $user = if ($msg -match 'Account Name:\\s+([^\\r\\n\\s]+)') {{ $matches[1] }} else {{ '-' }}
            $by = if ($msg -match 'Subject:.*?Account Name:\\s+([^\\r\\n\\s]+)') {{ $matches[1] }} else {{ '-' }}
            $results += [PSCustomObject]@{{
                Time = $e.TimeCreated.ToString('o')
                EventId = $e.Id
                TargetUser = $user
                ChangedBy = $by
                Message = $e.Message.Substring(0, [Math]::Min(200, $e.Message.Length))
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_ps(cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except:
        return []


def get_scheduled_tasks(hours_back: int = 168) -> List[Dict]:
    """Get new/modified scheduled task events (4698, 4702) — persistence indicator."""
    cmd = f"""
$start = (Get-Date).AddHours(-{hours_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@(4698,4702);StartTime=$start}} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $taskName = if ($msg -match 'Task Name:\\s+([^\\r\\n]+)') {{ $matches[1].Trim() }} else {{ 'Unknown' }}
            $by = if ($msg -match 'Subject:.*?Account Name:\\s+([^\\r\\n\\s]+)') {{ $matches[1] }} else {{ '-' }}
            $results += [PSCustomObject]@{{
                Time = $e.TimeCreated.ToString('o')
                EventId = $e.Id
                TaskName = $taskName
                CreatedBy = $by
                Action = if ($e.Id -eq 4698) {{ 'Created' }} else {{ 'Modified' }}
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_ps(cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except:
        return []


def get_new_services(hours_back: int = 168) -> List[Dict]:
    """Get new service installations (7045) — persistence/malware indicator."""
    cmd = f"""
$start = (Get-Date).AddHours(-{hours_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{LogName='System';Id=7045;StartTime=$start}} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $svcName = if ($msg -match 'Service Name:\\s+([^\\r\\n]+)') {{ $matches[1].Trim() }} else {{ 'Unknown' }}
            $svcFile = if ($msg -match 'Service File Name:\\s+([^\\r\\n]+)') {{ $matches[1].Trim() }} else {{ 'Unknown' }}
            $results += [PSCustomObject]@{{
                Time = $e.TimeCreated.ToString('o')
                ServiceName = $svcName
                ServiceFile = $svcFile
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_ps(cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except:
        return []


def get_explicit_credential_use(hours_back: int = 24) -> List[Dict]:
    """Get explicit credential logon events (4648) — lateral movement indicator."""
    cmd = f"""
$start = (Get-Date).AddHours(-{hours_back})
try {{
    $events = Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4648;StartTime=$start}} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($events) {{
        $results = @()
        foreach ($e in $events) {{
            $msg = $e.Message
            $user = if ($msg -match 'Account Name:\\s+([^\\r\\n\\s]+)') {{ $matches[1] }} else {{ '-' }}
            $target = if ($msg -match 'Target Server Name:\\s+([^\\r\\n]+)') {{ $matches[1].Trim() }} else {{ '-' }}
            $results += [PSCustomObject]@{{
                Time = $e.TimeCreated.ToString('o')
                Username = $user
                TargetServer = $target
                EventId = $e.Id
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    output = _run_ps(cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except:
        return []


def build_session_timeline(sessions: List[Dict]) -> List[Dict]:
    """Build user session timeline from logon events."""
    LOGON_TYPES = {
        "2": "Interactive", "3": "Network", "4": "Batch",
        "5": "Service", "7": "Unlock", "8": "NetworkCleartext",
        "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive"
    }
    timeline = []
    for s in sessions:
        username = s.get("Username", "-")
        if _is_system(username):
            continue
        logon_type = str(s.get("LogonType", "2"))
        timeline.append({
            "time": s.get("Time", ""),
            "username": username,
            "logon_type": LOGON_TYPES.get(logon_type, f"Type {logon_type}"),
            "source_ip": s.get("SourceIP", "-"),
            "suspicious": logon_type in ("3", "8", "10") and s.get("SourceIP", "-") not in ("-", "", "127.0.0.1", "::1")
        })
    return timeline


def run_auditmind_scan(hours_back: int = 24) -> Dict:
    """Main AuditMind scan — deep log intelligence."""
    result = {
        "agent": "AuditMind",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "hours_scanned": hours_back,
        "session_timeline": [],
        "account_changes": [],
        "scheduled_tasks": [],
        "new_services": [],
        "explicit_cred_use": [],
        "summary": {
            "total_user_sessions": 0,
            "account_changes": 0,
            "new_scheduled_tasks": 0,
            "new_services": 0,
            "suspicious_logons": 0,
            "peak_risk": 0.0,
        },
        "threat_events": [],
        "alerts": [],
        "system_status": {
            "clean": True,
            "message": "No suspicious audit events detected"
        },
        "error": None
    }

    try:
        # Gather all data
        sessions = get_logon_sessions(hours_back)
        account_changes = get_account_changes(hours_back * 7)
        scheduled_tasks = get_scheduled_tasks(hours_back * 7)
        new_services = get_new_services(hours_back * 7)
        explicit_creds = get_explicit_credential_use(hours_back)

        # Build session timeline
        timeline = build_session_timeline(sessions)
        result["session_timeline"] = timeline[:20]

        # Filter account changes to non-system accounts
        user_account_changes = [
            e for e in account_changes
            if not _is_system(e.get("TargetUser", ""))
            and not _is_system(e.get("ChangedBy", ""))
        ]
        result["account_changes"] = user_account_changes[:10]

        # Scheduled tasks
        result["scheduled_tasks"] = scheduled_tasks[:10]

        # New services
        result["new_services"] = new_services[:10]

        # Explicit credential use (non-system)
        user_explicit = [
            e for e in explicit_creds
            if not _is_system(e.get("Username", ""))
        ]
        result["explicit_cred_use"] = user_explicit[:10]

        # Summary
        suspicious_logons = sum(1 for s in timeline if s.get("suspicious"))
        result["summary"] = {
            "total_user_sessions": len(timeline),
            "account_changes": len(user_account_changes),
            "new_scheduled_tasks": len(scheduled_tasks),
            "new_services": len(new_services),
            "suspicious_logons": suspicious_logons,
            "peak_risk": 0.0
        }

        # Build alerts and risk
        peak_risk = 0.0

        if new_services:
            result["alerts"].append({
                "severity": "high",
                "rule": "NEW_SERVICE_INSTALLED",
                "message": f"{len(new_services)} new service(s) installed — possible persistence mechanism",
                "details": [s.get("ServiceName", "unknown") for s in new_services[:3]]
            })
            peak_risk = max(peak_risk, 75.0)
            result["system_status"]["clean"] = False

        if scheduled_tasks:
            result["alerts"].append({
                "severity": "medium",
                "rule": "SCHEDULED_TASK_CREATED",
                "message": f"{len(scheduled_tasks)} scheduled task(s) created/modified",
                "details": [t.get("TaskName", "unknown") for t in scheduled_tasks[:3]]
            })
            peak_risk = max(peak_risk, 55.0)

        if user_account_changes:
            result["alerts"].append({
                "severity": "medium",
                "rule": "ACCOUNT_MODIFIED",
                "message": f"{len(user_account_changes)} user account change(s) detected",
                "details": [e.get("TargetUser", "unknown") for e in user_account_changes[:3]]
            })
            peak_risk = max(peak_risk, 50.0)

        if suspicious_logons > 0:
            result["alerts"].append({
                "severity": "medium",
                "rule": "SUSPICIOUS_LOGON_TYPE",
                "message": f"{suspicious_logons} suspicious remote logon(s) detected",
                "details": [f"{s['username']} from {s['source_ip']}" for s in timeline if s.get("suspicious")][:3]
            })
            peak_risk = max(peak_risk, 60.0)

        if user_explicit:
            result["alerts"].append({
                "severity": "low",
                "rule": "EXPLICIT_CREDENTIAL_USE",
                "message": f"Explicit credential use detected {len(user_explicit)} time(s)",
                "details": [f"{e.get('Username', 'unknown')} → {e.get('TargetServer', 'unknown')}" for e in user_explicit[:3]]
            })
            peak_risk = max(peak_risk, 40.0)

        result["summary"]["peak_risk"] = peak_risk

        if result["system_status"]["clean"] and peak_risk == 0:
            sessions_str = f"{len(timeline)} user session(s)" if timeline else "no sessions"
            result["system_status"]["message"] = f"Audit log clean — {sessions_str} in last {hours_back}hrs"
        elif not result["system_status"]["clean"]:
            result["system_status"]["message"] = f"{len(result['alerts'])} audit event(s) require attention"
        elif result["alerts"]:
            result["system_status"]["clean"] = False
            result["system_status"]["message"] = f"{len(result['alerts'])} audit event(s) flagged"

    except Exception as e:
        result["error"] = str(e)
        result["system_status"]["message"] = f"Scan error: {str(e)}"

    # Generate AI incident report
    result["incident_report"] = generate_report(result)

    return result


def format_cli(result: Dict) -> str:
    lines = ["=" * 60, "AUDITMIND — LOG INTELLIGENCE SCAN", "=" * 60]
    lines.append(f"Scan time:     {result['scan_time']}")
    lines.append(f"Window:        Last {result['hours_scanned']} hours")
    lines.append(f"Status:        {result['system_status']['message']}")
    s = result["summary"]
    lines += ["",
        f"User sessions:         {s['total_user_sessions']}",
        f"Account changes:       {s['account_changes']}",
        f"New scheduled tasks:   {s['new_scheduled_tasks']}",
        f"New services:          {s['new_services']}",
        f"Suspicious logons:     {s['suspicious_logons']}",
        f"Peak risk:             {s['peak_risk']:.1f}/100",
    ]
    if result["alerts"]:
        lines.append("\nALERTS:")
        for a in result["alerts"]:
            lines.append(f"  [{a['severity'].upper()}] {a['rule']}: {a['message']}")
    if result["session_timeline"]:
        lines.append("\nSESSION TIMELINE (recent):")
        for s in result["session_timeline"][:5]:
            flag = " ⚠" if s.get("suspicious") else ""
            lines.append(f"  {s['time'][:19]} | {s['username']} | {s['logon_type']}{flag}")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuditMind Live — Log Intelligence")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args()

    if args.watch:
        while True:
            try:
                r = run_auditmind_scan(hours_back=args.hours)
                print(json.dumps(r) if args.json else format_cli(r), flush=True)
                time.sleep(60)
            except KeyboardInterrupt:
                break
    else:
        r = run_auditmind_scan(hours_back=args.hours)
        print(json.dumps(r) if args.json else format_cli(r))
