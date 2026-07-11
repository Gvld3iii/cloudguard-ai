"""
CloudGuard AI — Download Protection Watcher
Monitors the Downloads folder for new files and auto-scans them.
Alerts through the Electron dashboard via stdout JSON stream.

Usage:
    python download_watcher.py                    # watch default Downloads folder
    python download_watcher.py --path <folder>    # watch custom folder
    python download_watcher.py --json             # JSON output for Electron IPC
    python download_watcher.py --once             # scan existing files once, then exit
"""

import os
import sys
import json
import time
import argparse
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional, Callable

# Path setup
_THIS_DIR = Path(__file__).parent
for p in [str(_THIS_DIR), str(_THIS_DIR / '..' / '..' / '..'),
          str(_THIS_DIR / '..' / '..'), str(_THIS_DIR / '..')]:
    if p not in sys.path:
        sys.path.insert(0, os.path.abspath(p))

# Import scanner
try:
    from phagekiller_scanner import scan_file, _compile_yara_rules, get_scanner_status
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

# Import watchdog for file system events
WATCHDOG_AVAILABLE = False
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    pass


# ── Default watch paths ───────────────────────────────────────────────────────
def get_default_watch_paths() -> List[Path]:
    """Get default folders to watch on Windows."""
    paths = []
    user_home = Path.home()

    candidates = [
        user_home / "Downloads",
        user_home / "Desktop",
        Path("C:/Users") / os.environ.get("USERNAME", "") / "Downloads",
    ]

    for p in candidates:
        if p.exists() and p not in paths:
            paths.append(p)

    return paths if paths else [Path.home() / "Downloads"]


# ── Skip list — files to ignore ───────────────────────────────────────────────
SKIP_EXTENSIONS = {
    ".tmp", ".crdownload", ".part", ".download",  # incomplete downloads
    ".db", ".sqlite", ".log",                       # databases/logs
    ".lnk", ".url",                                 # shortcuts
    ".ini", ".cfg",                                 # config files
}

SKIP_PREFIXES = {"."}  # hidden files

MIN_FILE_SIZE = 512  # bytes — skip tiny files


def _should_scan(filepath: Path) -> bool:
    """Determine if a file should be scanned."""
    # Skip incomplete downloads
    if filepath.suffix.lower() in SKIP_EXTENSIONS:
        return False

    # Skip hidden files
    if any(filepath.name.startswith(p) for p in SKIP_PREFIXES):
        return False

    # Skip if file too small
    try:
        if filepath.stat().st_size < MIN_FILE_SIZE:
            return False
    except (OSError, FileNotFoundError):
        return False

    return True


def _format_scan_result_for_dashboard(result: Dict, watch_path: str) -> Dict:
    """Format scan result for Electron IPC consumption."""
    verdict = result.get("verdict", "clean")
    severity = result.get("severity", "low")
    risk = result.get("risk_score", 0)

    # Map verdict to dashboard severity
    sev_map = {
        "malicious": "critical",
        "suspicious": "high",
        "clean": "low",
        "error": "medium"
    }

    return {
        "type": "download_scan",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": result.get("filename", "unknown"),
        "filepath": result.get("file", ""),
        "watch_path": watch_path,
        "verdict": verdict,
        "severity": sev_map.get(verdict, "low"),
        "risk_score": risk,
        "action": result.get("action", "allow"),
        "reasons": result.get("reasons", []),
        "yara_matches": result.get("yara_matches", []),
        "file_hash": result.get("file_hash", ""),
        "file_size": result.get("file_size", 0),
        "hash_match": result.get("hash_match"),
        "blocked": verdict == "malicious",
        "agent": "PhageKiller"
    }


class DownloadEventHandler(FileSystemEventHandler):
    """Handles file system events in watched folders."""

    def __init__(self, watch_path: str, json_mode: bool = False,
                 on_result: Optional[Callable] = None, compiled_rules=None):
        self.watch_path = watch_path
        self.json_mode = json_mode
        self.on_result = on_result
        self.compiled_rules = compiled_rules
        self._scanning = set()
        self._scan_lock = threading.Lock()
        self.scan_results = []

    def _scan_file_async(self, filepath: str):
        """Scan file in background thread."""
        with self._scan_lock:
            if filepath in self._scanning:
                return
            self._scanning.add(filepath)

        def do_scan():
            # Wait briefly for file to finish writing
            time.sleep(1.5)

            path = Path(filepath)
            if not path.exists() or not _should_scan(path):
                with self._scan_lock:
                    self._scanning.discard(filepath)
                return

            # Wait for file to stop changing size
            last_size = -1
            for _ in range(5):
                try:
                    current_size = path.stat().st_size
                    if current_size == last_size and current_size > 0:
                        break
                    last_size = current_size
                    time.sleep(0.5)
                except OSError:
                    break

            # Scan
            result = scan_file(filepath, compiled_rules=self.compiled_rules)
            dashboard_result = _format_scan_result_for_dashboard(result, self.watch_path)
            self.scan_results.append(dashboard_result)

            # Output
            if self.json_mode:
                print(json.dumps(dashboard_result), flush=True)
            else:
                self._print_result(dashboard_result)

            if self.on_result:
                self.on_result(dashboard_result)

            with self._scan_lock:
                self._scanning.discard(filepath)

        thread = threading.Thread(target=do_scan, daemon=True)
        thread.start()

    def _print_result(self, result: Dict):
        """Print scan result to console."""
        icons = {"malicious": "✗ BLOCKED", "suspicious": "⚠ WARNING", "clean": "✓ CLEAN", "error": "? ERROR"}
        icon = icons.get(result["verdict"], "? UNKNOWN")
        print(f"\n[PhageKiller] {icon} — {result['file']}")
        print(f"  Risk: {result['risk_score']}/100 | Action: {result['action'].upper()}")
        if result["reasons"]:
            for r in result["reasons"]:
                print(f"  → {r}")
        if result["yara_matches"]:
            for m in result["yara_matches"]:
                print(f"  → YARA [{m['severity'].upper()}] {m['rule']}")

    def on_created(self, event):
        if not event.is_directory:
            self._scan_file_async(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            path = Path(event.src_path)
            # Only scan on modification if it looks like a completed download
            if path.suffix.lower() not in SKIP_EXTENSIONS:
                self._scan_file_async(event.src_path)


def scan_existing_files(watch_paths: List[Path], json_mode: bool = False,
                        max_files: int = 20) -> List[Dict]:
    """Scan existing files in watch folders (most recent first)."""
    if not SCANNER_AVAILABLE:
        return []

    compiled_rules = _compile_yara_rules()
    all_results = []

    for watch_path in watch_paths:
        if not watch_path.exists():
            continue

        # Get all scannable files, sorted by modification time (newest first)
        files = []
        for f in watch_path.iterdir():
            if f.is_file() and _should_scan(f):
                try:
                    files.append((f.stat().st_mtime, f))
                except OSError:
                    pass

        files.sort(reverse=True)
        files = [f for _, f in files[:max_files]]

        if json_mode:
            startup_msg = {
                "type": "scanner_startup",
                "watch_path": str(watch_path),
                "files_to_scan": len(files),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            print(json.dumps(startup_msg), flush=True)

        for filepath in files:
            result = scan_file(str(filepath), compiled_rules=compiled_rules)
            dashboard_result = _format_scan_result_for_dashboard(result, str(watch_path))
            all_results.append(dashboard_result)

            if json_mode:
                print(json.dumps(dashboard_result), flush=True)

    return all_results


def start_watching(watch_paths: List[Path], json_mode: bool = False,
                   on_result: Optional[Callable] = None):
    """Start watching folders for new downloads."""
    if not WATCHDOG_AVAILABLE:
        # Fallback: poll every 5 seconds
        return _polling_watch(watch_paths, json_mode, on_result)

    compiled_rules = _compile_yara_rules() if SCANNER_AVAILABLE else None
    observer = Observer()
    handlers = []

    for watch_path in watch_paths:
        if not watch_path.exists():
            watch_path.mkdir(parents=True, exist_ok=True)

        handler = DownloadEventHandler(
            watch_path=str(watch_path),
            json_mode=json_mode,
            on_result=on_result,
            compiled_rules=compiled_rules
        )
        observer.schedule(handler, str(watch_path), recursive=False)
        handlers.append(handler)

        if json_mode:
            startup = {
                "type": "watcher_started",
                "watch_path": str(watch_path),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "watchdog_mode": True,
                "scanner_available": SCANNER_AVAILABLE
            }
            print(json.dumps(startup), flush=True)
        else:
            print(f"[PhageKiller] Watching: {watch_path}")

    observer.start()
    return observer, handlers


def _polling_watch(watch_paths: List[Path], json_mode: bool = False,
                   on_result: Optional[Callable] = None):
    """Fallback polling-based watcher when watchdog is not available."""
    known_files = {}
    compiled_rules = _compile_yara_rules() if SCANNER_AVAILABLE else None

    for watch_path in watch_paths:
        if watch_path.exists():
            for f in watch_path.iterdir():
                if f.is_file():
                    try:
                        known_files[str(f)] = f.stat().st_mtime
                    except OSError:
                        pass

    if json_mode:
        print(json.dumps({
            "type": "watcher_started",
            "watch_paths": [str(p) for p in watch_paths],
            "mode": "polling",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), flush=True)

    while True:
        time.sleep(3)
        for watch_path in watch_paths:
            if not watch_path.exists():
                continue
            try:
                current_files = {}
                for f in watch_path.iterdir():
                    if f.is_file():
                        try:
                            current_files[str(f)] = f.stat().st_mtime
                        except OSError:
                            pass

                # Find new files
                new_files = set(current_files.keys()) - set(known_files.keys())
                for filepath in new_files:
                    path = Path(filepath)
                    if _should_scan(path):
                        time.sleep(1)  # wait for write to complete
                        result = scan_file(filepath, compiled_rules=compiled_rules)
                        dashboard_result = _format_scan_result_for_dashboard(result, str(watch_path))

                        if json_mode:
                            print(json.dumps(dashboard_result), flush=True)
                        else:
                            print(f"\n[PhageKiller] New file: {path.name}")

                        if on_result:
                            on_result(dashboard_result)

                known_files.update(current_files)
                # Remove deleted files from tracking
                for k in list(known_files.keys()):
                    if k not in current_files:
                        del known_files[k]

            except (OSError, PermissionError):
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudGuard AI — Download Protection Watcher")
    parser.add_argument("--path", nargs="+", help="Folders to watch (default: Downloads)")
    parser.add_argument("--json", action="store_true", help="JSON output for Electron IPC")
    parser.add_argument("--once", action="store_true", help="Scan existing files once then exit")
    parser.add_argument("--status", action="store_true", help="Show watcher status")
    args = parser.parse_args()

    if args.status:
        status = {
            "watchdog_available": WATCHDOG_AVAILABLE,
            "scanner_available": SCANNER_AVAILABLE,
            "default_paths": [str(p) for p in get_default_watch_paths()],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        print(json.dumps(status) if args.json else json.dumps(status, indent=2))
        sys.exit(0)

    # Determine watch paths
    if args.path:
        watch_paths = [Path(p) for p in args.path]
    else:
        watch_paths = get_default_watch_paths()

    if args.once:
        # Scan existing files once
        results = scan_existing_files(watch_paths, json_mode=args.json)
        if not args.json:
            clean = sum(1 for r in results if r["verdict"] == "clean")
            threats = sum(1 for r in results if r["verdict"] in ("malicious", "suspicious"))
            print(f"\nScan complete: {len(results)} files — {clean} clean, {threats} threats")
        sys.exit(0)

    # Start watching
    if not args.json:
        print("CloudGuard AI — PhageKiller Download Protection")
        print("=" * 50)
        print(f"Watchdog: {'Available' if WATCHDOG_AVAILABLE else 'Polling mode'}")
        print(f"Scanner:  {'Available' if SCANNER_AVAILABLE else 'Not available'}")
        print(f"Watching: {', '.join(str(p) for p in watch_paths)}")
        print("Press Ctrl+C to stop.\n")

    try:
        result = start_watching(watch_paths, json_mode=args.json)
        if WATCHDOG_AVAILABLE and isinstance(result, tuple):
            observer, _ = result
            observer.join()
        # polling mode loops internally
    except KeyboardInterrupt:
        if not args.json:
            print("\n[PhageKiller] Stopped.")
