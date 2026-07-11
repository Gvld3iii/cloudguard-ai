"""
VaultGuard — Live Secrets Scanner
Scans real files on the filesystem for exposed credentials, API keys,
tokens, and hardcoded secrets using the existing VaultGuard analyzer.

Targets:
  - .env files anywhere on the system
  - AWS credentials (~/.aws/credentials, ~/.aws/config)
  - SSH keys (~/.ssh/)
  - Source code files (.py, .js, .ts, .yaml, .yml, .json, .config)
  - Desktop and common working directories
  - Recently modified files

Usage:
    python vaultguard_live.py              # scan common locations
    python vaultguard_live.py --json       # JSON output for Electron IPC
    python vaultguard_live.py --watch      # watch + scan continuously
    python vaultguard_live.py --path <dir> # scan specific directory
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional

# Path setup
_THIS_DIR = Path(__file__).parent
for p in [str(_THIS_DIR), str(_THIS_DIR / '..' / '..'), str(_THIS_DIR / '..' / '..' / '..'), str(_THIS_DIR / '..' / '..' / '..' / '..')]:
    if p not in sys.path:
        sys.path.insert(0, os.path.abspath(p))

try:
    from vaultguard import analyze
    from core.models import VaultGuardPayload, ThreatEvent
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False


# ── File targets ──────────────────────────────────────────────────────────────
HOME = Path.home()

# High priority — almost always contain secrets
HIGH_PRIORITY_PATHS = [
    HOME / ".aws" / "credentials",
    HOME / ".aws" / "config",
    HOME / ".ssh",
    HOME / ".env",
    HOME / "Desktop",
    Path("C:/Users") / os.environ.get("USERNAME", "") / ".aws" / "credentials",
]

# Extensions to scan for secrets in text content
SCANNABLE_EXTENSIONS = {
    ".env", ".env.local", ".env.development", ".env.production",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".config",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".pem", ".key", ".p12", ".pfx", ".crt", ".cer",
    ".txt", ".log", ".md",
    ".tf", ".tfvars",  # Terraform
    ".docker", ".dockerfile",
    ".properties", ".xml",
}

# Skip these folders
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".pytest_cache", "dist", "build", ".next", ".nuxt",
    "site-packages", "AppData", "Windows", "Program Files",
    "Program Files (x86)", ".cache", "Temp", "tmp"
}

# Skip files larger than 2MB
MAX_FILE_SIZE = 2 * 1024 * 1024

# Common secret-bearing filenames to always check
PRIORITY_FILENAMES = {
    ".env", ".env.local", ".env.dev", ".env.prod", ".env.test",
    "credentials", "secrets.json", "service-account.json",
    "config.json", "settings.py", "settings.js",
    "docker-compose.yml", "docker-compose.yaml",
    ".npmrc", ".pypirc", "terraform.tfvars",
    "id_rsa", "id_ed25519", "id_ecdsa",
}


def _is_scannable(filepath: Path) -> bool:
    """Check if a file should be scanned for secrets."""
    try:
        if not filepath.is_file():
            return False
        if filepath.stat().st_size > MAX_FILE_SIZE:
            return False
        if filepath.stat().st_size == 0:
            return False
        name = filepath.name.lower()
        if name in PRIORITY_FILENAMES:
            return True
        ext = filepath.suffix.lower()
        return ext in SCANNABLE_EXTENSIONS
    except (OSError, PermissionError):
        return False


def _read_file_safe(filepath: Path) -> Optional[str]:
    """Safely read file content."""
    try:
        return filepath.read_text(encoding="utf-8", errors="ignore")
    except (IOError, OSError, PermissionError):
        return None


def _get_scan_targets(root_path: Optional[Path] = None, max_files: int = 500) -> List[Path]:
    """Build list of files to scan."""
    targets = set()

    scan_roots = []

    if root_path:
        scan_roots = [root_path]
    else:
        # Default scan locations
        scan_roots = [
            HOME / ".aws",
            HOME / ".ssh",
            HOME / "Desktop",
            HOME / "Documents",
            Path("C:/Users") / os.environ.get("USERNAME", "") / "Desktop",
        ]

        # Add common dev locations
        dev_paths = [
            HOME / "projects",
            HOME / "dev",
            HOME / "code",
            HOME / "workspace",
            Path("C:/dev"),
            Path("C:/projects"),
        ]
        for p in dev_paths:
            if p.exists():
                scan_roots.append(p)

        # Priority single files
        for path in HIGH_PRIORITY_PATHS:
            if path.is_file() and _is_scannable(path):
                targets.add(path)

    # Walk directories
    for root in scan_roots:
        if not root.exists():
            continue
        try:
            if root.is_file():
                if _is_scannable(root):
                    targets.add(root)
                continue

            for filepath in root.rglob("*"):
                # Skip excluded directories
                if any(skip in filepath.parts for skip in SKIP_DIRS):
                    continue
                if _is_scannable(filepath):
                    targets.add(filepath)

                if len(targets) >= max_files:
                    break
        except (PermissionError, OSError):
            continue

    return list(targets)[:max_files]


def scan_file_for_secrets(filepath: Path) -> Optional[Dict]:
    """
    Scan a single file for secrets using VaultGuard analyzer.
    Returns result dict or None if nothing found / can't scan.
    """
    if not ANALYZER_AVAILABLE:
        return None

    content = _read_file_safe(filepath)
    if not content:
        return None

    try:
        payload = VaultGuardPayload(
            content=content,
            source=str(filepath),
            scan_depth="full"
        )
        events = analyze(payload)

        if not events:
            return None

        # Build result
        worst_severity = "low"
        peak_risk = 0.0
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for event in events:
            sev = event.severity.value if hasattr(event.severity, 'value') else str(event.severity)
            if sev_order.get(sev, 0) > sev_order.get(worst_severity, 0):
                worst_severity = sev
            if event.risk_score > peak_risk:
                peak_risk = event.risk_score

        return {
            "file": filepath.name,
            "filepath": str(filepath),
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "findings": len(events),
            "severity": worst_severity,
            "risk_score": round(peak_risk, 1),
            "events": [
                {
                    "rule": e.rule,
                    "description": e.description,
                    "severity": e.severity.value if hasattr(e.severity, 'value') else str(e.severity),
                    "risk_score": e.risk_score,
                    "action": e.action,
                    "metadata": e.metadata
                }
                for e in events
            ],
            "agent": "VaultGuard",
            "type": "secret_scan"
        }

    except Exception as e:
        return None


def run_vault_scan(root_path: Optional[str] = None, max_files: int = 300) -> Dict:
    """
    Main scan function — scans filesystem for exposed secrets.
    Returns structured results for Electron IPC.
    """
    result = {
        "agent": "VaultGuard",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "files_scanned": 0,
        "files_with_secrets": 0,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "peak_risk": 0.0,
        "findings": [],
        "scan_paths": [],
        "analyzer_available": ANALYZER_AVAILABLE,
        "error": None
    }

    if not ANALYZER_AVAILABLE:
        result["error"] = "VaultGuard analyzer not available — check PYTHONPATH"
        return result

    try:
        root = Path(root_path) if root_path else None
        targets = _get_scan_targets(root_path=root, max_files=max_files)
        result["files_scanned"] = len(targets)

        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for filepath in targets:
            finding = scan_file_for_secrets(filepath)
            if finding:
                result["files_with_secrets"] += 1
                result["total_findings"] += finding["findings"]
                result["findings"].append(finding)

                sev = finding["severity"]
                if sev == "critical":
                    result["critical_count"] += 1
                elif sev == "high":
                    result["high_count"] += 1
                elif sev == "medium":
                    result["medium_count"] += 1
                else:
                    result["low_count"] += 1

                if finding["risk_score"] > result["peak_risk"]:
                    result["peak_risk"] = finding["risk_score"]

        # Sort findings by risk score
        result["findings"].sort(key=lambda x: x["risk_score"], reverse=True)
        result["scan_paths"] = list(set(str(Path(f["filepath"]).parent) for f in result["findings"]))

    except Exception as e:
        result["error"] = str(e)

    return result


def format_cli_output(result: Dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("VAULTGUARD — LIVE SECRETS SCAN")
    lines.append("=" * 60)
    lines.append(f"Scan time:         {result['scan_time']}")
    lines.append(f"Files scanned:     {result['files_scanned']}")
    lines.append(f"Files with secrets:{result['files_with_secrets']}")
    lines.append(f"Total findings:    {result['total_findings']}")
    lines.append(f"Critical:          {result['critical_count']}")
    lines.append(f"High:              {result['high_count']}")
    lines.append(f"Medium:            {result['medium_count']}")
    lines.append(f"Low:               {result['low_count']}")
    lines.append(f"Peak risk:         {result['peak_risk']:.1f}/100")
    lines.append("")

    if result["findings"]:
        lines.append("SECRETS FOUND:")
        for finding in result["findings"][:10]:
            sev = finding["severity"].upper()
            lines.append(f"  [{sev}] {finding['file']} — {finding['findings']} finding(s)")
            lines.append(f"    Path: {finding['filepath']}")
            for event in finding["events"][:3]:
                lines.append(f"    → {event['rule']}: {event['description']}")
                lines.append(f"      Risk: {event['risk_score']} | Action: {event['action']}")
            lines.append("")
    else:
        lines.append("  No exposed secrets found.")

    if result.get("error"):
        lines.append(f"\nERROR: {result['error']}")

    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VaultGuard Live — Secrets Scanner")
    parser.add_argument("--json", action="store_true", help="JSON output for Electron IPC")
    parser.add_argument("--path", type=str, help="Path to scan (default: common locations)")
    parser.add_argument("--watch", action="store_true", help="Watch and rescan every 5 minutes")
    parser.add_argument("--max-files", type=int, default=300, help="Max files to scan")
    args = parser.parse_args()

    if args.watch:
        if not args.json:
            print("VaultGuard watching... (Ctrl+C to stop)")
        while True:
            try:
                result = run_vault_scan(root_path=args.path, max_files=args.max_files)
                if args.json:
                    print(json.dumps(result), flush=True)
                else:
                    print(format_cli_output(result))
                time.sleep(300)
            except KeyboardInterrupt:
                break
    else:
        result = run_vault_scan(root_path=args.path, max_files=args.max_files)
        if args.json:
            print(json.dumps(result))
        else:
            print(format_cli_output(result))
