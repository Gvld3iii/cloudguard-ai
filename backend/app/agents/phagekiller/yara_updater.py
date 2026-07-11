"""
CloudGuard AI — YARA Rule Auto-Updater
Pulls the latest YARA rules from top community repositories daily.
Rules are saved locally so PhageKiller always has fresh threat intelligence.

Sources:
  - Neo23x0/signature-base  (Florian Roth — most respected YARA researcher)
  - Yara-Rules/rules         (Main community repository)
  - MalwareBazaar hashes     (Daily malware hash feed)

Usage:
    python yara_updater.py              # update if older than 24hrs
    python yara_updater.py --force      # force update regardless of age
    python yara_updater.py --status     # show current rule status
"""

import os
import sys
import json
import time
import shutil
import hashlib
import argparse
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
_THIS_DIR = Path(__file__).parent
_RULES_DIR = _THIS_DIR / "rules"
_META_FILE = _RULES_DIR / "update_meta.json"
_BACKUP_DIR = _RULES_DIR / "backup"

# ── Rule sources ──────────────────────────────────────────────────────────────
RULE_SOURCES = [
    {
        "name": "signature-base-gen",
        "description": "Florian Roth — General malware signatures",
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar",
        "filename": "gen_webshells.yar",
        "priority": "high"
    },
    {
        "name": "signature-base-apt",
        "description": "Florian Roth — APT detection rules",
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_apt41.yar",
        "filename": "apt_apt41.yar",
        "priority": "critical"
    },
    {
        "name": "signature-base-suspicious",
        "description": "Florian Roth — Suspicious strings detection",
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_suspicious_strings.yar",
        "filename": "gen_suspicious_strings.yar",
        "priority": "critical"
    },
    {
        "name": "signature-base-malware",
        "description": "Florian Roth — Generic malware detection",
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_malware_generic.yar",
        "filename": "crime_malware_generic.yar",
        "priority": "critical"
    },
    {
        "name": "yara-rules-malware",
        "description": "Community — Malware family rules",
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT1.yar",
        "filename": "community_apt1.yar",
        "priority": "high"
    },
    {
        "name": "yara-rules-packer",
        "description": "Community — Packer and obfuscation detection",
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer.yar",
        "filename": "community_packers.yar",
        "priority": "medium"
    },
    {
        "name": "cloudguard-custom",
        "description": "CloudGuard AI — Custom rules for common threats",
        "url": None,  # local only
        "filename": "cloudguard_custom.yar",
        "priority": "high"
    }
]

# ── Custom CloudGuard YARA rules ──────────────────────────────────────────────
CLOUDGUARD_CUSTOM_RULES = """
/*
 * CloudGuard AI — Custom YARA Rules
 * Built-in rules targeting common threats on Windows systems
 * Updated: auto-generated
 */

rule CG_Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell scripts downloading and executing payloads"
        author = "CloudGuard AI"
        severity = "high"
        reference = "CloudGuard ThreatHound Intel"

    strings:
        $ps1 = "IEX" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "DownloadString" nocase
        $ps4 = "WebClient" nocase
        $ps5 = "FromBase64String" nocase
        $ps6 = "EncodedCommand" nocase

    condition:
        2 of ($ps1, $ps2, $ps3, $ps4) or
        ($ps5 and $ps6)
}

rule CG_Credential_Harvester
{
    meta:
        description = "Detects credential harvesting patterns"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $cred3 = "mimikatz" nocase
        $cred4 = "sekurlsa" nocase
        $cred5 = "lsass" nocase
        $dump1 = "procdump" nocase
        $dump2 = "comsvcs.dll" nocase

    condition:
        $cred3 or $cred4 or
        ($cred5 and 1 of ($dump1, $dump2)) or
        (all of ($cred1, $cred2) and 1 of ($dump1, $dump2))
}

rule CG_Ransomware_Pattern
{
    meta:
        description = "Detects common ransomware behavioral patterns"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $enc1 = "CryptEncrypt" nocase
        $enc2 = "CryptoAPI" nocase
        $ransom1 = "YOUR FILES" nocase
        $ransom2 = "DECRYPT" nocase
        $ransom3 = "bitcoin" nocase
        $ransom4 = "tor browser" nocase
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypto" nocase
        $vss1 = "vssadmin" nocase
        $vss2 = "delete shadows" nocase

    condition:
        ($vss1 and $vss2) or
        (2 of ($ransom1, $ransom2, $ransom3, $ransom4)) or
        (1 of ($enc1, $enc2) and 1 of ($ext1, $ext2, $ext3))
}

rule CG_Reverse_Shell
{
    meta:
        description = "Detects reverse shell payloads"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $nc1 = "nc -e" nocase
        $nc2 = "ncat" nocase
        $bash1 = "/bin/bash -i" nocase
        $bash2 = "bash -i >& /dev/tcp" nocase
        $ps_rev = "System.Net.Sockets.TCPClient" nocase
        $py_rev = "socket.connect" nocase

    condition:
        any of them
}

rule CG_Crypto_Miner
{
    meta:
        description = "Detects cryptocurrency mining software"
        author = "CloudGuard AI"
        severity = "high"

    strings:
        $miner1 = "xmrig" nocase
        $miner2 = "stratum+tcp" nocase
        $miner3 = "monero" nocase
        $miner4 = "nicehash" nocase
        $miner5 = "cryptonight" nocase
        $miner6 = "--donate-level" nocase
        $pool1 = "pool.minexmr" nocase
        $pool2 = "supportxmr.com" nocase

    condition:
        2 of them
}

rule CG_Suspicious_PE_Executable
{
    meta:
        description = "Detects suspicious PE executables with known bad indicators"
        author = "CloudGuard AI"
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $sus1 = "This program cannot be run in DOS mode"
        $anti1 = "IsDebuggerPresent"
        $anti2 = "CheckRemoteDebuggerPresent"
        $inject1 = "VirtualAllocEx"
        $inject2 = "WriteProcessMemory"
        $inject3 = "CreateRemoteThread"

    condition:
        $mz at 0 and
        $sus1 and
        (2 of ($inject1, $inject2, $inject3) or
         all of ($anti1, $anti2))
}

rule CG_Webshell_Generic
{
    meta:
        description = "Detects common webshell patterns"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "base64_decode(" nocase
        $php4 = "system(" nocase
        $php5 = "exec(" nocase
        $php6 = "shell_exec(" nocase
        $php7 = "passthru(" nocase
        $asp1 = "<%@ Page" nocase
        $asp2 = "cmd.exe" nocase

    condition:
        ($php1 and 2 of ($php2, $php3, $php4, $php5, $php6, $php7)) or
        ($asp1 and $asp2)
}
"""


def _ensure_dirs():
    """Create rules directories if they don't exist."""
    _RULES_DIR.mkdir(parents=True, exist_ok=True)
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _load_meta() -> Dict:
    """Load update metadata."""
    if _META_FILE.exists():
        try:
            return json.loads(_META_FILE.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {"last_update": None, "rules": {}, "total_rules": 0}


def _save_meta(meta: Dict):
    """Save update metadata."""
    _META_FILE.write_text(json.dumps(meta, indent=2))


def _needs_update(meta: Dict) -> bool:
    """Check if rules need updating (older than 24 hours)."""
    last = meta.get("last_update")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
        return datetime.now(timezone.utc) - last_dt > timedelta(hours=24)
    except (ValueError, TypeError):
        return True


def _write_custom_rules():
    """Write CloudGuard custom YARA rules."""
    custom_path = _RULES_DIR / "cloudguard_custom.yar"
    custom_path.write_text(CLOUDGUARD_CUSTOM_RULES)
    return True


def _download_rule(source: Dict, timeout: int = 15) -> bool:
    """Download a single YARA rule file."""
    if source.get("url") is None:
        # Local/custom rule
        if source["filename"] == "cloudguard_custom.yar":
            return _write_custom_rules()
        return False

    url = source["url"]
    dest = _RULES_DIR / source["filename"]

    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "CloudGuard-AI/1.0 YARA-Updater"
        })

        if resp.status_code == 200 and len(resp.text) > 100:
            # Backup existing rule if present
            if dest.exists():
                shutil.copy2(dest, _BACKUP_DIR / source["filename"])

            dest.write_text(resp.text, encoding="utf-8")
            return True
        else:
            print(f"  ✗ {source['name']} — HTTP {resp.status_code}")
            return False

    except requests.RequestException as e:
        print(f"  ✗ {source['name']} — {str(e)[:60]}")
        return False


def _count_rules_in_file(filepath: Path) -> int:
    """Count the number of YARA rules in a file."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        return content.count("\nrule ") + content.count("^rule ")
    except IOError:
        return 0


def update_rules(force: bool = False, verbose: bool = True) -> Dict:
    """
    Main update function — downloads latest YARA rules.
    Returns summary of what was updated.
    """
    _ensure_dirs()
    meta = _load_meta()

    if not force and not _needs_update(meta):
        if verbose:
            print(f"Rules are up to date (last updated: {meta.get('last_update', 'unknown')})")
            print("Use --force to update anyway.")
        return {"updated": False, "reason": "up_to_date", "meta": meta}

    if verbose:
        print("CloudGuard AI — YARA Rule Updater")
        print("=" * 50)
        print(f"Updating {len(RULE_SOURCES)} rule sources...")
        print()

    results = {"updated": [], "failed": [], "total_rules": 0}

    for source in RULE_SOURCES:
        if verbose:
            print(f"  Fetching {source['name']}... ", end="", flush=True)

        success = _download_rule(source)

        if success:
            rule_file = _RULES_DIR / source["filename"]
            count = _count_rules_in_file(rule_file)
            results["updated"].append({
                "name": source["name"],
                "filename": source["filename"],
                "rules": count,
                "priority": source["priority"]
            })
            if verbose:
                print(f"✓ ({count} rules)")
        else:
            results["failed"].append(source["name"])
            # Use backup if available
            backup = _BACKUP_DIR / source["filename"]
            if backup.exists():
                shutil.copy2(backup, _RULES_DIR / source["filename"])
                if verbose:
                    print(f"  → Using cached backup for {source['name']}")

    # Count total rules
    total = 0
    for yar_file in _RULES_DIR.glob("*.yar"):
        total += _count_rules_in_file(yar_file)
    results["total_rules"] = total

    # Update metadata
    meta["last_update"] = datetime.now(timezone.utc).isoformat()
    meta["rules"] = {r["name"]: r for r in results["updated"]}
    meta["total_rules"] = total
    meta["failed"] = results["failed"]
    _save_meta(meta)

    if verbose:
        print()
        print(f"Update complete:")
        print(f"  Updated:      {len(results['updated'])} sources")
        print(f"  Failed:       {len(results['failed'])} sources")
        print(f"  Total rules:  {total}")
        print(f"  Rules dir:    {_RULES_DIR}")

    return results


def get_status() -> Dict:
    """Get current rule status without updating."""
    _ensure_dirs()
    meta = _load_meta()

    rule_files = list(_RULES_DIR.glob("*.yar"))
    total_rules = sum(_count_rules_in_file(f) for f in rule_files)
    needs = _needs_update(meta)

    return {
        "last_update": meta.get("last_update"),
        "needs_update": needs,
        "total_rules": total_rules,
        "rule_files": len(rule_files),
        "rules_dir": str(_RULES_DIR),
        "sources": len(RULE_SOURCES)
    }


def get_rule_files() -> List[Path]:
    """Get list of all local YARA rule files."""
    _ensure_dirs()
    # Always ensure custom rules exist
    custom = _RULES_DIR / "cloudguard_custom.yar"
    if not custom.exists():
        _write_custom_rules()
    return list(_RULES_DIR.glob("*.yar"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudGuard AI — YARA Rule Updater")
    parser.add_argument("--force", action="store_true", help="Force update regardless of age")
    parser.add_argument("--status", action="store_true", help="Show current rule status")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.status:
        status = get_status()
        if args.json:
            print(json.dumps(status))
        else:
            print("CloudGuard AI — YARA Rule Status")
            print("=" * 40)
            print(f"Last update:   {status['last_update'] or 'Never'}")
            print(f"Needs update:  {'Yes' if status['needs_update'] else 'No'}")
            print(f"Total rules:   {status['total_rules']}")
            print(f"Rule files:    {status['rule_files']}")
            print(f"Sources:       {status['sources']}")
            print(f"Rules dir:     {status['rules_dir']}")
    else:
        result = update_rules(force=args.force, verbose=not args.json)
        if args.json:
            print(json.dumps(result, default=str))
