#!/usr/bin/env python3
"""
Sentinel AI — CLI
Run all 5 agents from the terminal with colored output.

Usage:
    python cli/sentinel.py --scenario ransomware
    python cli/sentinel.py --scenario data_breach
    python cli/sentinel.py --scenario credential_theft
    python cli/sentinel.py --scenario insider_threat
    python cli/sentinel.py --scenario cryptominer
    python cli/sentinel.py --live   # interactive mode
"""

import sys, os, json, time, argparse, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
except ImportError:
    print("[error] pip install requests")
    sys.exit(1)

BASE = "http://localhost:8000"

# ── ANSI ──────────────────────────────────────────────────────────────────────
R="\033[0m"; BOLD="\033[1m"; RED="\033[91m"; YEL="\033[93m"
GRN="\033[92m"; CYN="\033[96m"; MAG="\033[95m"; BLU="\033[94m"; GRY="\033[90m"

AGENT_COLOURS = {
    "ThreatHound":  CYN,
    "VaultGuard":   MAG,
    "NetSentinel":  BLU,
    "PhageKiller":  RED,
    "AuditMind":    YEL,
}

SEV_COLOURS = {
    "critical": RED,
    "high":     YEL,
    "medium":   CYN,
    "low":      GRN,
}

SEV_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

AGENT_ICONS = {
    "ThreatHound":  "🐕",
    "VaultGuard":   "🔐",
    "NetSentinel":  "🌐",
    "PhageKiller":  "🦠",
    "AuditMind":    "🧠",
}


def risk_bar(score: float, width: int = 20) -> str:
    filled = round(score / 100 * width)
    col    = RED if score >= 80 else YEL if score >= 50 else GRN
    return f"{col}{'█' * filled}{'░' * (width - filled)}{R}"


def print_banner():
    print(f"\n{BOLD}{MAG}{'═'*62}")
    print(f"  🛡️  SENTINEL AI  —  5-Agent Security Platform")
    print(f"{'═'*62}{R}\n")
    agents = [
        ("ThreatHound",  CYN, "Intrusion Detection"),
        ("VaultGuard",   MAG, "Secrets & Credentials"),
        ("NetSentinel",  BLU, "Network Analysis"),
        ("PhageKiller",  RED, "Malware & Process Monitor"),
        ("AuditMind",    YEL, "Log Intelligence"),
    ]
    for name, col, desc in agents:
        print(f"  {AGENT_ICONS[name]} {col}{BOLD}{name:<14}{R}  {GRY}{desc}{R}")
    print()


def print_event(event: dict):
    agent = event.get("agent", "Unknown")
    sev   = event.get("severity", "low")
    score = event.get("risk_score", 0)
    col   = AGENT_COLOURS.get(agent, R)
    sc    = SEV_COLOURS.get(sev, R)
    icon  = SEV_ICONS.get(sev, "•")
    ai    = AGENT_ICONS.get(agent, "•")

    print(f"  {ai} {col}{BOLD}{agent:<14}{R} {icon} {sc}{sev.upper():<8}{R} "
          f"risk={sc}{score:>5.1f}{R} {risk_bar(score, 14)}")
    print(f"     {GRY}rule:{R} {event.get('rule','')}")
    print(f"     {GRY}desc:{R} {event.get('description','')[:72]}")
    print(f"     {GRY}action:{R} {BOLD}{event.get('action','')}{R}")
    print()


def print_report(report: dict, scenario: str = ""):
    if scenario:
        print(f"\n{BOLD}Scenario: {YEL}{scenario.upper()}{R}\n")

    events   = report.get("events", [])
    critical = report.get("critical_count", 0)
    high     = report.get("high_count", 0)
    medium   = report.get("medium_count", 0)
    low      = report.get("low_count", 0)
    peak     = report.get("peak_risk", 0)
    agents   = report.get("agents_active", [])

    print(f"{'─'*60}")
    print(f"  Total events : {BOLD}{len(events)}{R}  |  "
          f"Agents active: {CYN}{', '.join(agents)}{R}")
    print(f"  {RED}Critical: {critical}{R}  {YEL}High: {high}{R}  "
          f"{CYN}Medium: {medium}{R}  {GRN}Low: {low}{R}")
    print(f"  Peak risk    : {risk_bar(peak, 20)} {RED if peak>=80 else YEL}{peak:.1f}/100{R}")
    print(f"{'─'*60}\n")

    if not events:
        print(f"  {GRN}✓ No threats detected.{R}\n")
        return

    # Sort by risk desc
    for event in sorted(events, key=lambda e: e.get("risk_score", 0), reverse=True):
        print_event(event)


def run_scenario(scenario: str):
    try:
        r = requests.post(f"{BASE}/sentinel/simulate/{scenario}", timeout=10)
        data = r.json()
        if "error" in data:
            print(f"{RED}{data['error']}{R}")
            return
        print_report(data["report"], scenario)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[error] Cannot connect to Sentinel AI at {BASE}{R}")
        print(f"{GRY}Start the server: uvicorn api.main:app --reload{R}")


def live_mode():
    print(f"{BOLD}Live Mode — sending random threat events every 3 seconds.{R}")
    print(f"{GRY}Press Ctrl+C to stop.{R}\n")
    SCENARIOS = ["ransomware", "data_breach", "credential_theft", "insider_threat", "cryptominer"]
    count = 0
    try:
        while True:
            count += 1
            sc = random.choice(SCENARIOS)
            print(f"{GRY}[{count:04d}] Running scenario: {sc}{R}")
            run_scenario(sc)
            time.sleep(3)
    except KeyboardInterrupt:
        print(f"\n{GRY}Live mode stopped after {count} scans.{R}\n")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Sentinel AI CLI")
    parser.add_argument("--scenario", choices=["ransomware","data_breach","credential_theft","insider_threat","cryptominer"])
    parser.add_argument("--all",  action="store_true", help="Run all 5 scenarios")
    parser.add_argument("--live", action="store_true", help="Live random mode")
    args = parser.parse_args()

    if args.live:
        live_mode()
    elif args.all:
        for sc in ["ransomware","data_breach","credential_theft","insider_threat","cryptominer"]:
            run_scenario(sc)
            time.sleep(0.5)
    elif args.scenario:
        run_scenario(args.scenario)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()