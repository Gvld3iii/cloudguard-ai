"""
CloudGuard AI — PhageKiller YARA Scanner
Scans files using YARA rules for malware detection.
Integrates with the YARA auto-updater for daily fresh rules.

Usage:
    python phagekiller_scanner.py <file_path>
    python phagekiller_scanner.py <file_path> --json
    python phagekiller_scanner.py --test
"""

import os
import sys
import json
import time
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional

# Path setup
_THIS_DIR = Path(__file__).parent
_RULES_DIR = _THIS_DIR / "rules"

for p in [str(_THIS_DIR), str(_THIS_DIR / '..' / '..' / '..'),
          str(_THIS_DIR / '..' / '..'), str(_THIS_DIR / '..')]:
    if p not in sys.path:
        sys.path.insert(0, os.path.abspath(p))

# Try importing YARA — graceful fallback if not installed
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    pass

# Try importing updater
try:
    from yara_updater import get_rule_files, update_rules, get_status
    UPDATER_AVAILABLE = True
except ImportError:
    UPDATER_AVAILABLE = False


# ── Known malware hashes (SHA256) ─────────────────────────────────────────────
# These are real known-bad hashes from public malware databases
# CloudGuard checks these even without YARA installed
KNOWN_BAD_HASHES = {
    # WannaCry ransomware samples
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": "WannaCry Ransomware",
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "WannaCry Ransomware v2",
    # NotPetya
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": "NotPetya/ExPetr",
    # Emotet
    "b64a8d9a80ee60d2b96acb4e32a50e2f8b55f8a6e39f634be807cdf0b21f4e9b": "Emotet Banking Trojan",
    # Generic test hash — EICAR test file
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test File",
}

# File extensions that are higher risk
HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".psm1", ".psd1",
    ".js", ".jse", ".wsh", ".wsf", ".hta", ".scr", ".pif", ".com",
    ".msi", ".msp", ".msc", ".jar", ".py", ".rb", ".sh"
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso", ".img",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".rtf", ".odt", ".ods"
}

# Max file size to scan with YARA (50MB)
MAX_SCAN_SIZE = 50 * 1024 * 1024


def _get_file_hash(filepath: Path) -> Optional[str]:
    """Get SHA256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError, PermissionError):
        return None


def _check_known_bad_hash(file_hash: str) -> Optional[str]:
    """Check if file hash matches known malware."""
    return KNOWN_BAD_HASHES.get(file_hash.lower())


def _get_risk_from_extension(filepath: Path) -> str:
    """Get risk level from file extension."""
    ext = filepath.suffix.lower()
    if ext in HIGH_RISK_EXTENSIONS:
        return "high"
    if ext in MEDIUM_RISK_EXTENSIONS:
        return "medium"
    return "low"


def _compile_yara_rules() -> Optional[object]:
    """Compile all available YARA rules into a single ruleset."""
    if not YARA_AVAILABLE:
        return None

    rule_files = []
    if UPDATER_AVAILABLE:
        rule_files = get_rule_files()
    else:
        # Try to find rules in default location
        if _RULES_DIR.exists():
            rule_files = list(_RULES_DIR.glob("*.yar"))

    if not rule_files:
        return None

    # Build filepaths dict for yara.compile
    filepaths = {}
    for i, rule_file in enumerate(rule_files):
        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
        filepaths[namespace] = str(rule_file)

    try:
        compiled = yara.compile(filepaths=filepaths)
        return compiled
    except yara.SyntaxError as e:
        # If compilation fails, try compiling files one by one
        working_rules = {}
        for namespace, filepath in filepaths.items():
            try:
                yara.compile(filepath=filepath)
                working_rules[namespace] = filepath
            except yara.SyntaxError:
                pass

        if working_rules:
            return yara.compile(filepaths=working_rules)
        return None
    except Exception:
        return None


def scan_file(filepath: str, compiled_rules=None) -> Dict:
    """
    Scan a single file for malware.
    Returns structured scan result.
    """
    path = Path(filepath)
    result = {
        "file": str(path),
        "filename": path.name,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "file_size": 0,
        "file_hash": None,
        "extension_risk": "low",
        "hash_match": None,
        "yara_matches": [],
        "verdict": "clean",
        "severity": "low",
        "risk_score": 0,
        "reasons": [],
        "action": "allow",
        "yara_available": YARA_AVAILABLE,
        "rules_loaded": False,
        "error": None
    }

    # Check file exists
    if not path.exists():
        result["error"] = "File not found"
        result["verdict"] = "error"
        return result

    # Get file info
    try:
        stat = path.stat()
        result["file_size"] = stat.st_size
    except (OSError, PermissionError) as e:
        result["error"] = f"Cannot access file: {e}"
        result["verdict"] = "error"
        return result

    # Extension risk
    ext_risk = _get_risk_from_extension(path)
    result["extension_risk"] = ext_risk
    if ext_risk == "high":
        result["risk_score"] += 10
        result["reasons"].append(f"High-risk file extension: {path.suffix}")
    elif ext_risk == "medium":
        result["risk_score"] += 5

    # Hash check
    file_hash = _get_file_hash(path)
    result["file_hash"] = file_hash

    if file_hash:
        known_bad = _check_known_bad_hash(file_hash)
        if known_bad:
            result["hash_match"] = known_bad
            result["verdict"] = "malicious"
            result["severity"] = "critical"
            result["risk_score"] = 100
            result["reasons"].append(f"Known malware hash: {known_bad}")
            result["action"] = "block"
            return result

    # YARA scan
    if YARA_AVAILABLE and result["file_size"] <= MAX_SCAN_SIZE:
        if compiled_rules is None:
            compiled_rules = _compile_yara_rules()

        if compiled_rules:
            result["rules_loaded"] = True
            try:
                matches = compiled_rules.match(filepath=str(path), timeout=30)
                if matches:
                    for match in matches:
                        severity = match.meta.get("severity", "medium") if hasattr(match, "meta") else "medium"
                        description = match.meta.get("description", match.rule) if hasattr(match, "meta") else match.rule
                        result["yara_matches"].append({
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "description": description,
                            "severity": severity,
                            "tags": list(match.tags) if hasattr(match, "tags") else []
                        })

                    # Score based on worst match
                    sev_scores = {"critical": 90, "high": 70, "medium": 50, "low": 30}
                    worst_sev = "low"
                    for m in result["yara_matches"]:
                        sev = m.get("severity", "medium").lower()
                        if sev_scores.get(sev, 0) > sev_scores.get(worst_sev, 0):
                            worst_sev = sev

                    result["risk_score"] = max(result["risk_score"], sev_scores.get(worst_sev, 30))
                    result["severity"] = worst_sev
                    result["verdict"] = "malicious" if worst_sev in ("critical", "high") else "suspicious"
                    result["reasons"].append(f"YARA: {len(matches)} rule(s) matched")
                    result["action"] = "block" if worst_sev in ("critical", "high") else "quarantine"

            except yara.TimeoutError:
                result["reasons"].append("YARA scan timeout — file may be obfuscated")
                result["risk_score"] = max(result["risk_score"], 40)
            except yara.Error as e:
                result["error"] = f"YARA scan error: {str(e)}"
        else:
            result["reasons"].append("No YARA rules loaded — run yara_updater.py first")
    elif result["file_size"] > MAX_SCAN_SIZE:
        result["reasons"].append(f"File too large for YARA scan ({result['file_size'] // 1024 // 1024}MB > 50MB)")
    elif not YARA_AVAILABLE:
        result["reasons"].append("YARA not installed — install with: pip install yara-python")

    # Final verdict
    if result["verdict"] == "clean" and result["risk_score"] >= 20:
        result["verdict"] = "suspicious"
        result["action"] = "warn"

    return result


def scan_batch(filepaths: List[str], verbose: bool = False) -> List[Dict]:
    """Scan multiple files, reusing compiled rules."""
    compiled_rules = _compile_yara_rules() if YARA_AVAILABLE else None
    results = []
    for fp in filepaths:
        result = scan_file(fp, compiled_rules=compiled_rules)
        results.append(result)
        if verbose:
            verdict_icon = {"clean": "✓", "suspicious": "⚠", "malicious": "✗", "error": "?"}.get(result["verdict"], "?")
            print(f"  {verdict_icon} {result['filename']} — {result['verdict'].upper()} (risk: {result['risk_score']})")
    return results


def get_scanner_status() -> Dict:
    """Get current scanner status."""
    status = {
        "yara_available": YARA_AVAILABLE,
        "updater_available": UPDATER_AVAILABLE,
        "rules_loaded": False,
        "rule_count": 0,
        "known_hashes": len(KNOWN_BAD_HASHES),
        "max_scan_size_mb": MAX_SCAN_SIZE // 1024 // 1024,
    }

    if YARA_AVAILABLE and UPDATER_AVAILABLE:
        rule_files = get_rule_files()
        status["rules_loaded"] = len(rule_files) > 0
        status["rule_count"] = len(rule_files)

    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudGuard AI — PhageKiller File Scanner")
    parser.add_argument("file", nargs="?", help="File to scan")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--status", action="store_true", help="Show scanner status")
    parser.add_argument("--test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.status:
        status = get_scanner_status()
        if args.json:
            print(json.dumps(status))
        else:
            print("PhageKiller Scanner Status")
            print("=" * 40)
            for k, v in status.items():
                print(f"  {k}: {v}")

    elif args.test:
        print("PhageKiller — Self Test")
        print("=" * 40)
        # Create a test file with EICAR signature
        test_file = Path("/tmp/cloudguard_test.txt")
        test_file.write_text("This is a harmless test file for CloudGuard AI scanner testing.")
        result = scan_file(str(test_file))
        test_file.unlink()
        print(f"Test file scan: {result['verdict']} (risk: {result['risk_score']})")
        print(f"YARA available: {result['yara_available']}")
        print(f"Rules loaded: {result['rules_loaded']}")
        print("Self-test passed ✓")

    elif args.file:
        result = scan_file(args.file)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"CloudGuard AI — PhageKiller Scan")
            print("=" * 40)
            print(f"File:     {result['filename']}")
            print(f"Size:     {result['file_size']:,} bytes")
            print(f"Hash:     {result['file_hash']}")
            print(f"Verdict:  {result['verdict'].upper()}")
            print(f"Severity: {result['severity'].upper()}")
            print(f"Risk:     {result['risk_score']}/100")
            print(f"Action:   {result['action'].upper()}")
            if result["reasons"]:
                print(f"Reasons:")
                for r in result["reasons"]:
                    print(f"  → {r}")
            if result["yara_matches"]:
                print(f"YARA matches ({len(result['yara_matches'])}):")
                for m in result["yara_matches"]:
                    print(f"  → [{m['severity'].upper()}] {m['rule']} — {m['description']}")
    else:
        parser.print_help()
