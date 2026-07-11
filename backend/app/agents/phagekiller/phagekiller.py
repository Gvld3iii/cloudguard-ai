"""
PhageKiller — Malware & Process Monitor Agent
Monitors running processes for ransomware patterns, cryptominers,
reverse shells, suspicious parent-child relationships, and fileless attacks.
"""

from core.models import PhageKillerPayload, ThreatEvent, AgentName, Severity
from typing import List

AGENT = AgentName.PHAGEKILLER

# Known malware process names
KNOWN_MALWARE = {
    "mimikatz", "meterpreter", "cobalt", "empire", "metasploit",
    "nc.exe", "ncat", "netcat", "xmrig", "cpuminer", "cgminer",
    "wannacry", "petya", "cryptolocker", "locky", "ryuk",
    "psexec", "wce.exe", "pwdump", "fgdump",
}

# Suspicious parent → child combos (parent spawns unexpected child)
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "excel.exe":      {"cmd.exe", "powershell.exe", "wscript.exe"},
    "outlook.exe":    {"cmd.exe", "powershell.exe"},
    "iexplore.exe":   {"cmd.exe", "powershell.exe", "wscript.exe"},
    "chrome.exe":     {"cmd.exe", "powershell.exe"},
    "acrobat.exe":    {"cmd.exe", "powershell.exe"},
    "svchost.exe":    {"cmd.exe"},
    "explorer.exe":   {"powershell.exe", "wscript.exe", "cscript.exe"},
}

# System paths — executables running from unusual places are suspicious
SUSPICIOUS_PATHS = ["/tmp/", "/var/tmp/", "C:\\Users\\Public\\", "C:\\Temp\\",
                    "C:\\Windows\\Temp\\", "%APPDATA%", "AppData\\Local\\Temp"]

# Cryptominer indicators
MINER_NAMES = {"xmrig", "cpuminer", "bfgminer", "cgminer", "ethminer", "t-rex", "phoenixminer"}


def _is_known_malware(name: str) -> bool:
    return name.lower() in KNOWN_MALWARE

def _is_miner(name: str, cpu: float) -> bool:
    return name.lower() in MINER_NAMES or cpu > 90.0

def _suspicious_parent_child(parent: str, child: str) -> bool:
    parent_l = parent.lower()
    child_l  = child.lower()
    return child_l in SUSPICIOUS_PARENT_CHILD.get(parent_l, set())

def _suspicious_path(path: str) -> bool:
    return any(sus in path for sus in SUSPICIOUS_PATHS)


def analyze(payload: PhageKillerPayload) -> List[ThreatEvent]:
    events: List[ThreatEvent] = []
    name = payload.process_name

    # ── Rule 1: Known Malware Process ────────────────────────────────────────
    if _is_known_malware(name):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "KNOWN_MALWARE_PROCESS",
            description = f"Known malware process detected: {name} (PID {payload.pid})",
            severity    = Severity.CRITICAL,
            risk_score  = 100.0,
            action      = "kill_process_immediate",
            metadata    = {
                "process": name, "pid": payload.pid,
                "path":    payload.file_path,
            },
        ))

    # ── Rule 2: Cryptominer Detection ────────────────────────────────────────
    if _is_miner(name, payload.cpu_percent):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "CRYPTOMINER_DETECTED",
            description = f"Cryptominer activity: {name} consuming {payload.cpu_percent:.1f}% CPU",
            severity    = Severity.HIGH,
            risk_score  = 87.0,
            action      = "kill_process",
            metadata    = {
                "process":     name, "pid": payload.pid,
                "cpu_percent": payload.cpu_percent,
            },
        ))

    # ── Rule 3: Ransomware Pattern ───────────────────────────────────────────
    if payload.file_ops_per_sec >= 200 and payload.cpu_percent > 30:
        severity = Severity.CRITICAL if payload.file_ops_per_sec >= 500 else Severity.HIGH
        risk     = min(100, 60 + payload.file_ops_per_sec * 0.08)
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "RANSOMWARE_PATTERN",
            description = f"Ransomware-like activity: {name} — {payload.file_ops_per_sec} file ops/sec",
            severity    = severity,
            risk_score  = round(risk, 1),
            action      = "kill_process_isolate_host",
            metadata    = {
                "process":          name, "pid": payload.pid,
                "file_ops_per_sec": payload.file_ops_per_sec,
                "cpu_percent":      payload.cpu_percent,
            },
        ))

    # ── Rule 4: Suspicious Parent-Child ──────────────────────────────────────
    if payload.parent_process and _suspicious_parent_child(payload.parent_process, name):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "SUSPICIOUS_PROCESS_SPAWN",
            description = f"Suspicious spawn: {payload.parent_process} → {name} (possible macro/exploit)",
            severity    = Severity.HIGH,
            risk_score  = 83.0,
            action      = "kill_process",
            metadata    = {
                "parent":  payload.parent_process,
                "child":   name,
                "pid":     payload.pid,
            },
        ))

    # ── Rule 5: Process with Unexpected Network Connections ──────────────────
    if payload.network_connections > 50 and name not in {"chrome.exe", "firefox.exe", "node", "python"}:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "PROCESS_NET_ANOMALY",
            description = f"Process {name} has {payload.network_connections} unexpected network connections",
            severity    = Severity.HIGH,
            risk_score  = 76.0,
            action      = "alert_and_monitor",
            metadata    = {
                "process":             name, "pid": payload.pid,
                "network_connections": payload.network_connections,
            },
        ))

    # ── Rule 6: Suspicious File Path ─────────────────────────────────────────
    if payload.file_path and _suspicious_path(payload.file_path):
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "SUSPICIOUS_EXEC_PATH",
            description = f"Process {name} running from suspicious path: {payload.file_path}",
            severity    = Severity.MEDIUM,
            risk_score  = 62.0,
            action      = "alert",
            metadata    = {"process": name, "pid": payload.pid, "path": payload.file_path},
        ))

    # ── Rule 7: Process Spawning Many Children ────────────────────────────────
    if payload.spawned_children >= 20:
        events.append(ThreatEvent(
            agent       = AGENT,
            rule        = "PROCESS_FORK_BOMB",
            description = f"Fork bomb / aggressive spawning: {name} created {payload.spawned_children} children",
            severity    = Severity.HIGH,
            risk_score  = 80.0,
            action      = "kill_process_tree",
            metadata    = {
                "process":          name, "pid": payload.pid,
                "spawned_children": payload.spawned_children,
            },
        ))

    return events
