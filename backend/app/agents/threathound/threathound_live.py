"""
ThreatHound — Live Bridge
Connects real Windows Security Event Log to the existing analyzer.
Reads actual system events, builds ThreatHoundPayload objects,
runs them through existing detection rules, and outputs results.

Usage:
    python threathound_live.py              # run once
    python threathound_live.py --watch      # run every 30s
    python threathound_live.py --json       # JSON output for Electron IPC
    python threathound_live.py --minutes 60 # look back N minutes
"""

import sys
import json
import time
import os
import argparse
from datetime import datetime, timezone
from typing import List, Dict

# Path setup — works whether run directly or imported
_this_dir = os.path.dirname(os.path.abspath(__file__))
_backend_app = os.path.join(_this_dir, '..', '..', '..')
_core_path = os.path.join(_this_dir, '..', '..', '..')

for p in [_this_dir, os.path.join(_this_dir, '..', '..'), _backend_app]:
    if p not in sys.path:
        sys.path.insert(0, os.path.abspath(p))

try:
    from windows_event_reader import get_security_summary
    from analyzer import analyze
    from core.models import ThreatHoundPayload, ThreatEvent
except ImportError as e:
    if '--json' in sys.argv:
        print(json.dumps({"error": str(e), "events": [], "raw_stats": {}}))
    else:
        print(f"Import error: {e}")
        print("Run with: $env:PYTHONPATH = 'backend/app;backend'")
    sys.exit(1)


def build_payloads_from_summary(summary: Dict) -> List[ThreatHoundPayload]:
    """
    Convert real Windows security summary into ThreatHoundPayload objects
    compatible with the existing analyzer.
    """
    payloads = []
    minutes = summary.get("minutes_scanned", 60)

    # ── Failed login aggregates ───────────────────────────────────────────────
    for ip, data in summary.get("failed_logins", {}).items():
        if ip == "unknown":
            continue

        count = data.get("count", 0)
        is_external = data.get("is_external", False)
        is_known_bad = data.get("is_known_bad", False)

        if count < 1 and not is_known_bad:
            continue

        rpm = int((count / max(minutes, 1)) * 60)

        payload = ThreatHoundPayload(
            source_ip=ip,
            event_type="failed_login",
            failed_attempts=count,
            ports_scanned=0,
            requests_per_minute=rpm,
            geo_anomaly=is_external and count >= 3,
            known_bad_ip=is_known_bad,
        )
        payloads.append(payload)

    # ── Real user privilege escalations (not SYSTEM) ──────────────────────────
    user_escalations = summary.get("privilege_escalations", [])
    if len(user_escalations) >= 1:
        payload = ThreatHoundPayload(
            source_ip="localhost",
            event_type="privilege_escalation",
            failed_attempts=0,
            ports_scanned=0,
            requests_per_minute=len(user_escalations),
            geo_anomaly=False,
            known_bad_ip=False,
        )
        payloads.append(payload)

    # ── Audit policy tampering ────────────────────────────────────────────────
    audit_changes = summary.get("audit_policy_changes", [])
    if audit_changes:
        payload = ThreatHoundPayload(
            source_ip="localhost",
            event_type="audit_policy_tamper",
            failed_attempts=len(audit_changes),
            ports_scanned=0,
            requests_per_minute=0,
            geo_anomaly=False,
            known_bad_ip=True,
        )
        payloads.append(payload)

    return payloads


def run_threathound_live(minutes_back: int = 60) -> Dict:
    """
    Main entry point — reads real Windows events and runs ThreatHound analysis.
    Returns structured result for Electron IPC or CLI display.
    """
    result = {
        "agent": "ThreatHound",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "minutes_scanned": minutes_back,
        "events": [],
        "summary": {
            "total_events": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "peak_risk": 0.0,
        },
        "raw_stats": {
            "total_failed_logins": 0,
            "user_failed_logins": 0,
            "unique_source_ips": 0,
            "external_attackers": 0,
            "brute_force_candidates": 0,
            "user_privilege_escalations": 0,
            "system_privilege_events": 0,
            "audit_changes": 0,
            "recent_user_logins": 0,
        },
        "system_status": {
            "clean": True,
            "message": "No active threats detected",
            "last_user_login": None,
        },
        "windows_event_log_available": True,
        "error": None
    }

    try:
        # Step 1: Read real Windows Security events
        security_summary = get_security_summary(minutes_back=minutes_back)
        result["windows_event_log_available"] = security_summary.get("windows_event_log_available", True)

        if security_summary.get("error"):
            result["error"] = security_summary["error"]

        # Step 2: Update raw stats
        result["raw_stats"] = {
            "total_failed_logins": security_summary.get("total_failed_logins", 0),
            "user_failed_logins": len(security_summary.get("user_failed_logins", [])),
            "unique_source_ips": security_summary.get("unique_source_ips", 0),
            "external_attackers": len(security_summary.get("external_attack_ips", [])),
            "brute_force_candidates": len(security_summary.get("brute_force_candidates", [])),
            "user_privilege_escalations": len(security_summary.get("privilege_escalations", [])),
            "system_privilege_events": security_summary.get("privilege_escalations_system_count", 0),
            "audit_changes": len(security_summary.get("audit_policy_changes", [])),
            "recent_user_logins": len(security_summary.get("successful_logins", [])),
        }

        # Step 3: Build payloads and run through existing analyzer
        payloads = build_payloads_from_summary(security_summary)
        all_events: List[ThreatEvent] = []

        for payload in payloads:
            events = analyze(payload)
            all_events.extend(events)

        # Step 4: Sort by risk
        all_events.sort(key=lambda e: e.risk_score, reverse=True)

        # Step 5: Build result
        result["events"] = [e.model_dump() for e in all_events]
        result["summary"]["total_events"] = len(all_events)
        result["summary"]["critical"] = sum(1 for e in all_events if e.severity.value == "critical")
        result["summary"]["high"] = sum(1 for e in all_events if e.severity.value == "high")
        result["summary"]["medium"] = sum(1 for e in all_events if e.severity.value == "medium")
        result["summary"]["low"] = sum(1 for e in all_events if e.severity.value == "low")
        result["summary"]["peak_risk"] = all_events[0].risk_score if all_events else 0.0

        # Step 6: System status summary
        recent_logins = security_summary.get("successful_logins", [])
        if recent_logins:
            result["system_status"]["last_user_login"] = recent_logins[0].get("time")

        if all_events:
            result["system_status"]["clean"] = False
            result["system_status"]["message"] = f"{len(all_events)} threat(s) detected — peak risk {all_events[0].risk_score:.0f}/100"
        elif result["raw_stats"]["total_failed_logins"] > 0:
            result["system_status"]["message"] = f"{result['raw_stats']['total_failed_logins']} failed login(s) in last {minutes_back}min — below alert threshold"
        else:
            result["system_status"]["message"] = f"No threats in last {minutes_back} minutes — system clean"

    except Exception as e:
        result["error"] = str(e)
        result["windows_event_log_available"] = False
        result["system_status"]["message"] = f"Scan error: {str(e)}"

    return result


def format_cli_output(result: Dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("THREATHOUND — LIVE SECURITY SCAN")
    lines.append("=" * 60)
    lines.append(f"Scan time:      {result['scan_time']}")
    lines.append(f"Window:         Last {result['minutes_scanned']} minutes")
    lines.append(f"Event Log:      {'Available ✓' if result['windows_event_log_available'] else 'UNAVAILABLE — run as Admin'}")
    lines.append(f"Status:         {result['system_status']['message']}")
    if result['system_status']['last_user_login']:
        lines.append(f"Last login:     {result['system_status']['last_user_login']}")
    lines.append("")

    stats = result["raw_stats"]
    lines.append("WINDOWS SECURITY EVENTS:")
    lines.append(f"  Total failed logins:        {stats['total_failed_logins']}")
    lines.append(f"  User account failures:       {stats['user_failed_logins']}")
    lines.append(f"  Unique source IPs:           {stats['unique_source_ips']}")
    lines.append(f"  External attackers:          {stats['external_attackers']}")
    lines.append(f"  Brute force candidates:      {stats['brute_force_candidates']}")
    lines.append(f"  User privilege escalations:  {stats['user_privilege_escalations']}")
    lines.append(f"  System privilege events:     {stats['system_privilege_events']} (normal Windows behavior)")
    lines.append(f"  Audit policy changes:        {stats['audit_changes']}")
    lines.append(f"  Recent user logins:          {stats['recent_user_logins']}")
    lines.append("")

    summary = result["summary"]
    lines.append("THREAT ANALYSIS:")
    lines.append(f"  Total threat events:    {summary['total_events']}")
    lines.append(f"  Critical:               {summary['critical']}")
    lines.append(f"  High:                   {summary['high']}")
    lines.append(f"  Medium:                 {summary['medium']}")
    lines.append(f"  Low:                    {summary['low']}")
    lines.append(f"  Peak risk score:        {summary['peak_risk']:.1f}/100")
    lines.append("")

    if result["events"]:
        lines.append("DETECTED THREATS:")
        for event in result["events"][:10]:
            lines.append(f"  [{event['severity'].upper()}] {event['rule']}")
            lines.append(f"    {event['description']}")
            lines.append(f"    Risk: {event['risk_score']:.1f} | Action: {event['action']}")
            lines.append("")
    else:
        lines.append("  No active threats detected.")

    if result.get("error"):
        lines.append(f"\nERROR: {result['error']}")

    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatHound Live — Real Windows Security Monitor")
    parser.add_argument("--watch", action="store_true", help="Run continuously every 30 seconds")
    parser.add_argument("--json", action="store_true", help="Output JSON for Electron IPC")
    parser.add_argument("--minutes", type=int, default=1440, help="Minutes to look back (default: 1440 = 24hrs)")
    args = parser.parse_args()

    if args.watch:
        print("ThreatHound watching... (Ctrl+C to stop)")
        while True:
            try:
                result = run_threathound_live(minutes_back=args.minutes)
                if args.json:
                    print(json.dumps(result))
                    sys.stdout.flush()
                else:
                    print(format_cli_output(result))
                time.sleep(30)
            except KeyboardInterrupt:
                print("\nThreatHound stopped.")
                break
    else:
        result = run_threathound_live(minutes_back=args.minutes)
        if args.json:
            print(json.dumps(result))
        else:
            print(format_cli_output(result))
