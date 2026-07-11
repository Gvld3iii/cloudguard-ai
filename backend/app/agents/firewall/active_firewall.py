"""
CloudGuard AI — Active Firewall
Manages Windows Firewall rules to auto-block malicious IPs.
Triggered by ThreatHound and NetSentinel when threats are detected.

Usage:
    python active_firewall.py --block <ip>          # block an IP
    python active_firewall.py --unblock <ip>        # unblock an IP
    python active_firewall.py --list                # list blocked IPs
    python active_firewall.py --status              # firewall status
    python active_firewall.py --auto                # auto-block from threat scan
    python active_firewall.py --json                # JSON output
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

_THIS_DIR = Path(__file__).parent
BLOCK_LOG = _THIS_DIR / "firewall_blocks.json"
RULE_PREFIX = "CloudGuard-Block-"


def _run_ps(cmd: str, timeout: int = 15) -> tuple:
    """Run PowerShell command, return (success, output)."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, "", str(e)


def _load_block_log() -> Dict:
    if BLOCK_LOG.exists():
        try:
            return json.loads(BLOCK_LOG.read_text())
        except:
            pass
    return {"blocked_ips": {}, "total_blocked": 0, "last_updated": None}


def _save_block_log(log: Dict):
    log["last_updated"] = datetime.now(timezone.utc).isoformat()
    BLOCK_LOG.write_text(json.dumps(log, indent=2))


def check_admin() -> bool:
    """Check if running with admin privileges."""
    success, output, _ = _run_ps("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
    return output.strip().lower() == "true"


def get_firewall_status() -> Dict:
    """Get Windows Firewall status."""
    cmd = """
try {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $rules = Get-NetFirewallRule -DisplayName 'CloudGuard-Block-*' -ErrorAction SilentlyContinue
    $ruleCount = if ($rules) { @($rules).Count } else { 0 }
    [PSCustomObject]@{
        Profiles = $profiles
        CloudGuardRules = $ruleCount
    } | ConvertTo-Json -Depth 3
} catch { Write-Output '{}' }
"""
    success, output, _ = _run_ps(cmd)
    if not output or output == "{}":
        return {"enabled": False, "cloudguard_rules": 0}
    try:
        data = json.loads(output)
        profiles = data.get("Profiles", [])
        if isinstance(profiles, dict):
            profiles = [profiles]
        enabled = any(p.get("Enabled", False) for p in profiles) if profiles else False
        return {
            "enabled": enabled,
            "cloudguard_rules": data.get("CloudGuardRules", 0),
            "profiles": profiles
        }
    except:
        return {"enabled": False, "cloudguard_rules": 0}


def block_ip(ip: str, reason: str = "CloudGuard threat detection") -> Dict:
    """Block an IP address using Windows Firewall."""
    result = {
        "success": False,
        "ip": ip,
        "action": "block",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "message": "",
        "rule_name": f"{RULE_PREFIX}{ip.replace('.', '-')}"
    }

    # Validate IP
    parts = ip.split(".")
    if len(parts) != 4:
        result["message"] = f"Invalid IP address: {ip}"
        return result

    # Skip local IPs
    local_prefixes = ["127.", "192.168.", "10.", "172.16.", "::1"]
    if any(ip.startswith(p) for p in local_prefixes):
        result["message"] = f"Skipping local IP: {ip}"
        return result

    rule_name = result["rule_name"]

    # Add inbound block rule
    cmd_in = f"""
try {{
    $existing = Get-NetFirewallRule -DisplayName '{rule_name}-IN' -ErrorAction SilentlyContinue
    if (-not $existing) {{
        New-NetFirewallRule -DisplayName '{rule_name}-IN' -Direction Inbound -Action Block -RemoteAddress {ip} -Protocol Any -Description 'CloudGuard AI auto-block: {reason}' -ErrorAction Stop | Out-Null
    }}
    Write-Output 'OK'
}} catch {{
    Write-Output ('ERROR: ' + $_.Exception.Message)
}}
"""
    success_in, out_in, _ = _run_ps(cmd_in)

    # Add outbound block rule
    cmd_out = f"""
try {{
    $existing = Get-NetFirewallRule -DisplayName '{rule_name}-OUT' -ErrorAction SilentlyContinue
    if (-not $existing) {{
        New-NetFirewallRule -DisplayName '{rule_name}-OUT' -Direction Outbound -Action Block -RemoteAddress {ip} -Protocol Any -Description 'CloudGuard AI auto-block: {reason}' -ErrorAction Stop | Out-Null
    }}
    Write-Output 'OK'
}} catch {{
    Write-Output ('ERROR: ' + $_.Exception.Message)
}}
"""
    success_out, out_out, _ = _run_ps(cmd_out)

    if "OK" in out_in and "OK" in out_out:
        result["success"] = True
        result["message"] = f"IP {ip} blocked (inbound + outbound)"

        # Log the block
        log = _load_block_log()
        log["blocked_ips"][ip] = {
            "ip": ip,
            "reason": reason,
            "blocked_at": result["timestamp"],
            "rule_name": rule_name,
            "active": True
        }
        log["total_blocked"] = len(log["blocked_ips"])
        _save_block_log(log)
    elif "already" in out_in.lower() or "already" in out_out.lower():
        result["success"] = True
        result["message"] = f"IP {ip} already blocked"
    else:
        result["message"] = f"Failed to block {ip}: {out_in} | {out_out}"
        if "administrator" in out_in.lower() or "administrator" in out_out.lower():
            result["message"] = f"Admin privileges required to block {ip}"

    return result


def unblock_ip(ip: str) -> Dict:
    """Remove firewall block for an IP."""
    result = {
        "success": False,
        "ip": ip,
        "action": "unblock",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": ""
    }

    rule_name = f"{RULE_PREFIX}{ip.replace('.', '-')}"
    cmd = f"""
try {{
    $removed = 0
    $inRule = Get-NetFirewallRule -DisplayName '{rule_name}-IN' -ErrorAction SilentlyContinue
    if ($inRule) {{
        Remove-NetFirewallRule -DisplayName '{rule_name}-IN' -ErrorAction SilentlyContinue
        $removed++
    }}
    $outRule = Get-NetFirewallRule -DisplayName '{rule_name}-OUT' -ErrorAction SilentlyContinue
    if ($outRule) {{
        Remove-NetFirewallRule -DisplayName '{rule_name}-OUT' -ErrorAction SilentlyContinue
        $removed++
    }}
    Write-Output $removed
}} catch {{
    Write-Output ('ERROR: ' + $_.Exception.Message)
}}
"""
    success, output, _ = _run_ps(cmd)
    removed = 0
    try:
        removed = int(output.strip())
    except:
        pass

    if removed > 0:
        result["success"] = True
        result["message"] = f"IP {ip} unblocked ({removed} rules removed)"
        log = _load_block_log()
        if ip in log["blocked_ips"]:
            log["blocked_ips"][ip]["active"] = False
            log["blocked_ips"][ip]["unblocked_at"] = result["timestamp"]
        _save_block_log(log)
    elif "ERROR" in output:
        result["message"] = f"Error removing rules: {output}"
    else:
        result["message"] = f"No active block found for {ip}"
        result["success"] = True

    return result


def list_blocked_ips() -> Dict:
    """List all IPs currently blocked by CloudGuard."""
    cmd = f"""
try {{
    $rules = Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue
    if ($rules) {{
        $results = @()
        foreach ($r in $rules) {{
            $filter = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $results += [PSCustomObject]@{{
                Name = $r.DisplayName
                Direction = $r.Direction
                Enabled = $r.Enabled
                RemoteAddress = if ($filter) {{ $filter.RemoteAddress }} else {{ 'unknown' }}
            }}
        }}
        $results | ConvertTo-Json -Depth 2
    }} else {{ Write-Output '[]' }}
}} catch {{ Write-Output '[]' }}
"""
    success, output, _ = _run_ps(cmd)
    firewall_rules = []
    if output and output != "[]":
        try:
            data = json.loads(output)
            firewall_rules = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
        except:
            pass

    log = _load_block_log()
    return {
        "firewall_rules": firewall_rules,
        "cloudguard_blocks": log.get("blocked_ips", {}),
        "total_active": sum(1 for b in log.get("blocked_ips", {}).values() if b.get("active")),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def auto_block_threats() -> Dict:
    """Auto-block IPs from ThreatHound and NetSentinel scans."""
    result = {
        "blocked": [],
        "skipped": [],
        "failed": [],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Import threat data
    blocked_ips = set()
    block_log = _load_block_log()
    already_blocked = {ip for ip, data in block_log.get("blocked_ips", {}).items() if data.get("active")}

    # Try to get ThreatHound data
    try:
        th_script = _THIS_DIR.parent / "threathound" / "threathound_live.py"
        if th_script.exists():
            ps_result = subprocess.run(
                [sys.executable, str(th_script), "--json", "--minutes", "60"],
                capture_output=True, text=True, timeout=25,
                env={**os.environ, "PYTHONPATH": str(_THIS_DIR.parent.parent.parent)}
            )
            if ps_result.returncode == 0:
                th_data = json.loads(ps_result.stdout.strip())
                raw = th_data.get("raw_stats", {})
                for ip_data in th_data.get("findings", {}).get("external_attack_ips", []):
                    ip = ip_data.get("ip", "")
                    if ip and ip_data.get("count", 0) >= 5:
                        blocked_ips.add((ip, f"ThreatHound: {ip_data['count']} failed logins"))
    except Exception:
        pass

    # Try to get NetSentinel data
    try:
        ns_script = _THIS_DIR / "netsentinel_live.py"
        if ns_script.exists():
            ns_result = subprocess.run(
                [sys.executable, str(ns_script), "--json"],
                capture_output=True, text=True, timeout=25
            )
            if ns_result.returncode == 0:
                ns_data = json.loads(ns_result.stdout.strip())
                for c2 in ns_data.get("connections", {}).get("c2", []):
                    ip = c2.get("ip", "")
                    if ip:
                        blocked_ips.add((ip, f"NetSentinel: C2 connection detected"))
                for sus in ns_data.get("connections", {}).get("suspicious", []):
                    ip = sus.get("ip", "")
                    if ip:
                        blocked_ips.add((ip, f"NetSentinel: {sus.get('reason', 'suspicious')}"))
    except Exception:
        pass

    # Block each IP
    for ip, reason in blocked_ips:
        if ip in already_blocked:
            result["skipped"].append({"ip": ip, "reason": "already blocked"})
            continue
        block_result = block_ip(ip, reason)
        if block_result["success"]:
            result["blocked"].append({"ip": ip, "reason": reason})
        else:
            result["failed"].append({"ip": ip, "error": block_result["message"]})

    return result


def get_status() -> Dict:
    """Get complete firewall status."""
    fw_status = get_firewall_status()
    blocks = list_blocked_ips()
    is_admin = check_admin()

    return {
        "firewall_enabled": fw_status.get("enabled", False),
        "admin_privileges": is_admin,
        "cloudguard_rules": fw_status.get("cloudguard_rules", 0),
        "active_blocks": blocks.get("total_active", 0),
        "blocked_ips": list(blocks.get("cloudguard_blocks", {}).keys()),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudGuard AI — Active Firewall")
    parser.add_argument("--block", metavar="IP", help="Block an IP address")
    parser.add_argument("--unblock", metavar="IP", help="Unblock an IP address")
    parser.add_argument("--list", action="store_true", help="List blocked IPs")
    parser.add_argument("--status", action="store_true", help="Firewall status")
    parser.add_argument("--auto", action="store_true", help="Auto-block from threat scans")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.block:
        r = block_ip(args.block, "Manual CloudGuard block")
        print(json.dumps(r) if args.json else f"{'✓' if r['success'] else '✗'} {r['message']}")

    elif args.unblock:
        r = unblock_ip(args.unblock)
        print(json.dumps(r) if args.json else f"{'✓' if r['success'] else '✗'} {r['message']}")

    elif args.list:
        r = list_blocked_ips()
        if args.json:
            print(json.dumps(r))
        else:
            print(f"Active CloudGuard blocks: {r['total_active']}")
            for ip, data in r.get("cloudguard_blocks", {}).items():
                if data.get("active"):
                    print(f"  {ip} — {data.get('reason', 'unknown')} ({data.get('blocked_at', '')[:19]})")

    elif args.auto:
        r = auto_block_threats()
        if args.json:
            print(json.dumps(r))
        else:
            print(f"Auto-block complete: {len(r['blocked'])} blocked, {len(r['skipped'])} skipped, {len(r['failed'])} failed")
            for b in r["blocked"]:
                print(f"  ✓ Blocked {b['ip']}: {b['reason']}")

    else:
        r = get_status()
        if args.json:
            print(json.dumps(r))
        else:
            print("CloudGuard AI — Firewall Status")
            print("=" * 40)
            for k, v in r.items():
                print(f"  {k}: {v}")
