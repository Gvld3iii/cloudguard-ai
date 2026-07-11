"""
NetSentinel — Live Network Monitor
Reads real active network connections via PowerShell Get-NetTCPConnection.
Detects suspicious outbound connections, known C2 IPs, unusual ports,
and anomalous traffic patterns.

Usage:
    python netsentinel_live.py              # scan once
    python netsentinel_live.py --json       # JSON output for Electron IPC
    python netsentinel_live.py --watch      # continuous monitoring
"""

import os
import sys
import json
import time
import subprocess
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path
from collections import defaultdict

# Path setup
_THIS_DIR = Path(__file__).parent
for p in [str(_THIS_DIR), str(_THIS_DIR/'..'/'..'/'..'), str(_THIS_DIR/'..'/'..'), str(_THIS_DIR/'..'/'..')]:
    if p not in sys.path:
        sys.path.insert(0, os.path.abspath(p))

try:
    from analyzer import analyze as netsentinel_analyze
    from core.models import NetSentinelPayload, ThreatEvent
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False

# ── Known threat indicators ────────────────────────────────────────────────────
KNOWN_C2_PREFIXES = [
    "185.220.", "91.108.", "45.142.", "194.165.", "5.188.",
    "198.235.", "23.129.", "171.25.", "199.249.", "204.13.",
    "198.96.", "107.189.", "192.42.", "176.10.", "51.15.",
]

KNOWN_C2_PORTS = {
    4444, 4445, 1337, 31337, 8888, 9999,  # common C2
    6666, 6667, 6668, 6669,                # IRC C2
    1080, 3128, 8080, 8443,               # proxy/tunnel
}

SUSPICIOUS_PORTS = {
    22, 23, 3389, 5900, 5800,              # remote access
    1433, 3306, 5432, 6379, 27017, 9200,  # databases
    445, 135, 139,                          # SMB/RPC
    161, 162,                               # SNMP
}

TRUSTED_LOCAL = {"127.0.0.1", "::1", "0.0.0.0", "::"}

TRUSTED_PROCESSES = {
    "chrome", "firefox", "msedge", "brave",
    "svchost", "lsass", "explorer", "system",
    "onedrive", "dropbox", "discord", "teams",
    "spotify", "steam", "epicgames", "node",
    "python", "code", "windowsupdate",
}

# Known safe IP ranges
SAFE_PREFIXES = [
    "192.168.", "10.", "172.16.", "172.17.", "172.18.",
    "127.", "::1", "fe80:", "169.254.",
]

def _is_local(ip: str) -> bool:
    return any(ip.startswith(p) for p in SAFE_PREFIXES) or ip in TRUSTED_LOCAL

def _is_known_c2(ip: str) -> bool:
    return any(ip.startswith(p) for p in KNOWN_C2_PREFIXES)

def _run_powershell(cmd: str, timeout: int = 15) -> Optional[str]:
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


def get_active_connections() -> List[Dict]:
    """Get real active TCP connections via PowerShell."""
    ps_cmd = """
try {
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

    $results = @()
    foreach ($c in $conns) {
        $procName = ''
        try {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $procName = $proc.Name }
        } catch {}

        $results += [PSCustomObject]@{
            LocalAddress  = $c.LocalAddress
            LocalPort     = $c.LocalPort
            RemoteAddress = $c.RemoteAddress
            RemotePort    = $c.RemotePort
            State         = $c.State
            PID           = $c.OwningProcess
            Process       = $procName
        }
    }
    $results | ConvertTo-Json -Depth 2
} catch {
    Write-Output '[]'
}
"""
    output = _run_powershell(ps_cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def get_dns_cache() -> List[Dict]:
    """Get DNS cache entries to detect suspicious domain lookups."""
    ps_cmd = """
try {
    $dns = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, RecordType, Data, TimeToLive
    if ($dns) {
        $dns | ConvertTo-Json -Depth 2
    } else { Write-Output '[]' }
} catch { Write-Output '[]' }
"""
    output = _run_powershell(ps_cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def get_listening_ports() -> List[Dict]:
    """Get all listening ports."""
    ps_cmd = """
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess
    $results = @()
    foreach ($l in $listeners) {
        $procName = ''
        try {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $procName = $proc.Name }
        } catch {}
        $results += [PSCustomObject]@{
            Port    = $l.LocalPort
            Address = $l.LocalAddress
            PID     = $l.OwningProcess
            Process = $procName
        }
    }
    $results | ConvertTo-Json -Depth 2
} catch { Write-Output '[]' }
"""
    output = _run_powershell(ps_cmd)
    if not output or output.strip() == "[]":
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def analyze_connections(connections: List[Dict]) -> Dict:
    """Analyze connections for suspicious activity."""
    summary = {
        "total_connections": len(connections),
        "external_connections": [],
        "suspicious_connections": [],
        "c2_connections": [],
        "suspicious_ports": [],
        "unknown_processes": [],
        "connection_by_process": defaultdict(int),
        "unique_remote_ips": set(),
        "threat_events": [],
    }

    for conn in connections:
        remote_ip = conn.get("RemoteAddress", "")
        remote_port = conn.get("RemotePort", 0)
        local_port = conn.get("LocalPort", 0)
        proc_name = (conn.get("Process") or "").lower()
        state = conn.get("State", "")
        pid = conn.get("PID", 0)

        if not remote_ip or remote_ip in TRUSTED_LOCAL:
            continue

        summary["connection_by_process"][proc_name or "unknown"] += 1

        # Track unique remote IPs
        if not _is_local(remote_ip):
            summary["unique_remote_ips"].add(remote_ip)

        # External connections
        if not _is_local(remote_ip) and state == "Established":
            summary["external_connections"].append({
                "ip": remote_ip,
                "port": remote_port,
                "process": proc_name or "unknown",
                "pid": pid
            })

        # Known C2 IP
        if _is_known_c2(remote_ip):
            summary["c2_connections"].append({
                "ip": remote_ip,
                "port": remote_port,
                "process": proc_name or "unknown",
                "severity": "critical"
            })

        # Suspicious port
        if remote_port in KNOWN_C2_PORTS:
            summary["suspicious_connections"].append({
                "ip": remote_ip,
                "port": remote_port,
                "process": proc_name or "unknown",
                "reason": f"Known C2 port {remote_port}"
            })
        elif remote_port in SUSPICIOUS_PORTS and not _is_local(remote_ip):
            summary["suspicious_ports"].append({
                "ip": remote_ip,
                "port": remote_port,
                "process": proc_name or "unknown",
                "reason": f"Sensitive port {remote_port}"
            })

        # Unknown process with external connection
        if (not proc_name or proc_name == "unknown") and not _is_local(remote_ip):
            summary["unknown_processes"].append({
                "ip": remote_ip,
                "port": remote_port,
                "pid": pid
            })

    # Convert sets to lists
    summary["unique_remote_ips"] = list(summary["unique_remote_ips"])
    summary["connection_by_process"] = dict(summary["connection_by_process"])

    # Build threat events using analyzer if available
    if ANALYZER_AVAILABLE and (summary["c2_connections"] or summary["suspicious_connections"]):
        for c2 in summary["c2_connections"]:
            try:
                payload = NetSentinelPayload(
                    source_ip="localhost",
                    dest_ip=c2["ip"],
                    dest_port=c2["port"],
                    protocol="tcp",
                    bytes_sent=0,
                    bytes_received=0,
                    packet_count=1,
                    connection_duration_sec=0.0
                )
                events = netsentinel_analyze(payload)
                summary["threat_events"].extend([e.model_dump() for e in events])
            except Exception:
                pass

    return summary


def run_netsentinel_scan() -> Dict:
    """Main NetSentinel scan — returns structured results for Electron IPC."""
    result = {
        "agent": "NetSentinel",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "connections": {},
        "listening_ports": [],
        "dns_entries": 0,
        "summary": {
            "total": 0,
            "external": 0,
            "suspicious": 0,
            "c2_detected": 0,
            "peak_risk": 0.0,
        },
        "threat_events": [],
        "alerts": [],
        "system_status": {
            "clean": True,
            "message": "No suspicious network activity detected"
        },
        "error": None
    }

    try:
        connections = get_active_connections()
        listening = get_listening_ports()
        dns_cache = get_dns_cache()

        analysis = analyze_connections(connections)

        result["connections"] = {
            "total": analysis["total_connections"],
            "external": analysis["external_connections"][:10],
            "suspicious": analysis["suspicious_connections"][:5],
            "c2": analysis["c2_connections"],
            "by_process": dict(list(analysis["connection_by_process"].items())[:10]),
            "unique_remote_ips": len(analysis["unique_remote_ips"]),
        }

        result["listening_ports"] = [
            p for p in listening
            if p.get("Port", 0) not in {0, 80, 443, 135, 445, 49664, 49665}
        ][:15]

        result["dns_entries"] = len(dns_cache)

        result["summary"] = {
            "total": analysis["total_connections"],
            "external": len(analysis["external_connections"]),
            "suspicious": len(analysis["suspicious_connections"]) + len(analysis["c2_connections"]),
            "c2_detected": len(analysis["c2_connections"]),
            "peak_risk": 95.0 if analysis["c2_connections"] else
                        70.0 if analysis["suspicious_connections"] else
                        20.0 if analysis["external_connections"] else 0.0,
        }

        result["threat_events"] = analysis.get("threat_events", [])

        # Build alerts
        if analysis["c2_connections"]:
            result["alerts"].append({
                "severity": "critical",
                "message": f"C2 connection detected to {analysis['c2_connections'][0]['ip']}",
                "process": analysis["c2_connections"][0].get("process", "unknown")
            })
            result["system_status"] = {"clean": False, "message": f"C2 CONNECTION DETECTED — {len(analysis['c2_connections'])} threat(s)"}

        if analysis["suspicious_connections"]:
            for s in analysis["suspicious_connections"][:3]:
                result["alerts"].append({
                    "severity": "high",
                    "message": f"{s['reason']} — {s['process']} → {s['ip']}:{s['port']}",
                    "process": s.get("process", "unknown")
                })
            if result["system_status"]["clean"]:
                result["system_status"] = {
                    "clean": False,
                    "message": f"{len(analysis['suspicious_connections'])} suspicious connection(s) detected"
                }

        if result["system_status"]["clean"]:
            ext = len(analysis["external_connections"])
            result["system_status"]["message"] = (
                f"Network clean — {analysis['total_connections']} connections, "
                f"{ext} external, {len(analysis['unique_remote_ips'])} unique IPs"
            )

    except Exception as e:
        result["error"] = str(e)
        result["system_status"]["message"] = f"Scan error: {str(e)}"

    return result


def format_cli(result: Dict) -> str:
    lines = ["=" * 60, "NETSENTINEL — LIVE NETWORK SCAN", "=" * 60]
    lines.append(f"Scan time:    {result['scan_time']}")
    lines.append(f"Status:       {result['system_status']['message']}")
    s = result["summary"]
    lines += ["",
        f"Total connections:    {s['total']}",
        f"External:             {s['external']}",
        f"Suspicious:           {s['suspicious']}",
        f"C2 detected:          {s['c2_detected']}",
        f"Listening ports:      {len(result.get('listening_ports', []))}",
        f"DNS cache entries:    {result.get('dns_entries', 0)}",
    ]
    if result["alerts"]:
        lines.append("\nALERTS:")
        for a in result["alerts"]:
            lines.append(f"  [{a['severity'].upper()}] {a['message']}")
    if result["connections"].get("external"):
        lines.append("\nEXTERNAL CONNECTIONS:")
        for c in result["connections"]["external"][:5]:
            lines.append(f"  {c['process']} → {c['ip']}:{c['port']}")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel Live — Network Monitor")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()

    if args.watch:
        while True:
            try:
                r = run_netsentinel_scan()
                print(json.dumps(r) if args.json else format_cli(r), flush=True)
                time.sleep(args.interval)
            except KeyboardInterrupt:
                break
    else:
        r = run_netsentinel_scan()
        print(json.dumps(r) if args.json else format_cli(r))
