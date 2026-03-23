"""
dynamic.py — Sandboxed dynamic analysis for malware detection.

Runs the target file in an isolated subprocess and monitors:
  - Filesystem activity  (created / modified / deleted)
  - Network connections  (via psutil)
  - Child processes      (via psutil process tree)
  - stdout / stderr      (captured output)
  - Exit code & signals

Requirements:
    pip install psutil watchdog
"""

import logging
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── tuneable constants ────────────────────────────────────────────────────────
EXECUTION_TIMEOUT   = 15          # seconds before we forcibly kill the process
MONITOR_INTERVAL    = 0.2         # filesystem poll frequency (seconds)
MAX_OUTPUT_BYTES    = 4096        # cap stdout/stderr capture
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1",
    ".sh", ".bin", ".elf", ".so",
}
SUSPICIOUS_DIRS = {
    # Windows
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Users\\Public",
    os.path.expandvars("%APPDATA%"),
    os.path.expandvars("%TEMP%"),
    # Linux / macOS
    "/tmp",
    "/etc",
    "/usr/bin",
    "/usr/local/bin",
}
# ─────────────────────────────────────────────────────────────────────────────


# ── optional watchdog import ──────────────────────────────────────────────────
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer as WatchdogObserver
    _WATCHDOG_AVAILABLE = True
except ImportError:
    _WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not installed — filesystem monitoring disabled. "
                   "Run: pip install watchdog")

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed — network / process monitoring disabled. "
                   "Run: pip install psutil")
# ─────────────────────────────────────────────────────────────────────────────


# ── filesystem event collector ────────────────────────────────────────────────
class _FSEventCollector(FileSystemEventHandler if _WATCHDOG_AVAILABLE else object):
    """Collects filesystem events raised by watchdog."""

    def __init__(self):
        self.events: list[dict[str, str]] = []
        self._lock = threading.Lock()

    def _record(self, kind: str, path: str, dest: str | None = None):
        entry: dict[str, Any] = {"type": kind, "path": path}
        if dest:
            entry["dest"] = dest
        with self._lock:
            self.events.append(entry)

    def on_created(self, event):
        if not event.is_directory:
            self._record("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record("deleted", event.src_path)

    def on_moved(self, event):
        self._record("moved", event.src_path, getattr(event, "dest_path", None))

    def snapshot(self) -> list[dict[str, str]]:
        with self._lock:
            return list(self.events)
# ─────────────────────────────────────────────────────────────────────────────


def _get_network_connections(pid: int) -> list[dict]:
    """Return open network connections for *pid* using psutil."""
    if not _PSUTIL_AVAILABLE:
        return []
    try:
        proc = psutil.Process(pid)
        conns = proc.net_connections(kind="all")
        result = []
        for c in conns:
            result.append({
                "family":  str(c.family),
                "type":    str(c.type),
                "local":   f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status":  c.status or "",
            })
        return result
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def _get_child_processes(pid: int) -> list[dict]:
    """Return child processes spawned by *pid*."""
    if not _PSUTIL_AVAILABLE:
        return []
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        return [
            {
                "pid":    c.pid,
                "name":   c.name(),
                "status": c.status(),
                "exe":    _safe_exe(c),
            }
            for c in children
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def _safe_exe(proc) -> str:
    try:
        return proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return ""


def _build_command(file_path: str) -> list[str] | None:
    """
    Return the shell command to execute *file_path*, or None if it
    is not directly executable (e.g. a raw binary blob).
    """
    ext = Path(file_path).suffix.lower()
    system = platform.system()

    if ext == ".py":
        return [sys.executable, file_path]
    if ext in {".sh"} and system != "Windows":
        return ["bash", file_path]
    if ext in {".bat", ".cmd"} and system == "Windows":
        return ["cmd.exe", "/c", file_path]
    if ext == ".ps1" and system == "Windows":
        return ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", file_path]
    if ext in {".exe"} and system == "Windows":
        return [file_path]
    if ext in {".elf", ""} and system == "Linux":
        # Try to run as executable if the bit is set
        if os.access(file_path, os.X_OK):
            return [file_path]

    return None  # unknown / non-executable type


def _score_risk(result: dict) -> dict:
    """
    Assign a simple risk score and verdict based on collected indicators.
    """
    score = 0
    reasons: list[str] = []

    # ── filesystem indicators ─────────────────────────────────────────────
    fs_events: list[dict] = result.get("filesystem_events", [])
    for ev in fs_events:
        path_lower = ev.get("path", "").lower()
        ext = Path(path_lower).suffix

        if ext in SUSPICIOUS_EXTENSIONS:
            score += 15
            reasons.append(f"Dropped suspicious file: {ev['path']}")

        for sus_dir in SUSPICIOUS_DIRS:
            if path_lower.startswith(sus_dir.lower()):
                score += 20
                reasons.append(f"Wrote to sensitive directory: {ev['path']}")
                break

    # ── network indicators ────────────────────────────────────────────────
    net_conns: list[dict] = result.get("network_connections", [])
    if net_conns:
        score += 25 * min(len(net_conns), 2)
        reasons.append(f"Opened {len(net_conns)} network connection(s)")

    # ── child process indicators ──────────────────────────────────────────
    children: list[dict] = result.get("child_processes", [])
    if children:
        score += 10 * min(len(children), 3)
        names = [c["name"] for c in children]
        reasons.append(f"Spawned child process(es): {', '.join(names)}")

    # ── timeout (didn't terminate on its own) ─────────────────────────────
    if result.get("timed_out"):
        score += 30
        reasons.append("Process did not terminate within the time limit")

    # ── non-zero exit ─────────────────────────────────────────────────────
    exit_code = result.get("exit_code")
    if exit_code not in (0, None):
        score += 5
        reasons.append(f"Non-zero exit code: {exit_code}")

    # ── verdict ───────────────────────────────────────────────────────────
    score = min(score, 100)
    if score >= 60:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "risk_score": score,
        "verdict":    verdict,
        "reasons":    reasons,
    }


# ── public API ────────────────────────────────────────────────────────────────
def run_dynamic_analysis(file_path: str) -> dict:
    """
    Execute *file_path* in a monitored subprocess and return a report dict:

    {
        "executed":           bool,
        "exit_code":          int | None,
        "timed_out":          bool,
        "stdout":             str,
        "stderr":             str,
        "filesystem_events":  [ {type, path, ?dest} ],
        "network_connections":[ {family, type, local, remote, status} ],
        "child_processes":    [ {pid, name, status, exe} ],
        "risk":               {risk_score, verdict, reasons},
        "error":              str | None,
    }
    """
    result: dict[str, Any] = {
        "ran":                 False,
        "exit_code":           None,
        "timed_out":           False,
        "stdout":              "",
        "stderr":              "",
        "filesystem_events":   [],
        "network_connections": [],
        "child_processes":     [],
        "resource":            {},
        "risk":                {},
        "error":               None,
    }

    # ── 1. Decide how to run the file ──────────────────────────────────────
    cmd = _build_command(file_path)
    if cmd is None:
        result["error"] = (
            f"Cannot execute file type '{Path(file_path).suffix}' — "
            "dynamic analysis skipped."
        )
        result["risk"] = _score_risk(result)
        return result

    # ── 2. Set up filesystem monitoring in a temp watch directory ──────────
    #    We watch the system temp dir so we catch any files dropped there.
    watch_dir = tempfile.gettempdir()
    fs_collector = _FSEventCollector()
    observer = None

    if _WATCHDOG_AVAILABLE:
        observer = WatchdogObserver()
        observer.schedule(fs_collector, path=watch_dir, recursive=True)
        observer.start()

    # ── 3. Launch the subprocess ───────────────────────────────────────────
    proc = None
    try:
        logger.info(f"[dynamic] Launching: {cmd}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Isolate environment — strip most variables
            env={
                "PATH":    os.environ.get("PATH", ""),
                "TEMP":    tempfile.gettempdir(),
                "TMP":     tempfile.gettempdir(),
                "TMPDIR":  tempfile.gettempdir(),
                "HOME":    tempfile.gettempdir(),
            },
            # New process group so we can kill the whole tree
            **( {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                if platform.system() == "Windows"
                else {"start_new_session": True} ),
        )
        result["ran"] = True

        # ── 4. Collect network / child-process snapshots while it runs ───
        net_snapshots:  list[dict] = []
        child_snapshots: list[dict] = []

        deadline = time.monotonic() + EXECUTION_TIMEOUT
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            if _PSUTIL_AVAILABLE:
                net_snapshots.extend(_get_network_connections(proc.pid))
                child_snapshots.extend(_get_child_processes(proc.pid))
            time.sleep(MONITOR_INTERVAL)
        else:
            # Deadline hit — kill the entire process group
            result["timed_out"] = True
            logger.warning(f"[dynamic] Timeout — killing PID {proc.pid}")
            try:
                if platform.system() == "Windows":
                    subprocess.call(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    import signal
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception as kill_err:
                logger.error(f"[dynamic] Kill failed: {kill_err}")

        # ── 5. Gather output ──────────────────────────────────────────────
        try:
            stdout_raw, stderr_raw = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_raw, stderr_raw = proc.communicate()

        result["exit_code"] = proc.returncode
        result["stdout"]    = stdout_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        result["stderr"]    = stderr_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        # De-duplicate network / child snapshots
        seen_net   = set()
        seen_child = set()
        for conn in net_snapshots:
            key = (conn["local"], conn["remote"])
            if key not in seen_net:
                seen_net.add(key)
                result["network_connections"].append(conn)
        for child in child_snapshots:
            key = child["pid"]
            if key not in seen_child:
                seen_child.add(key)
                result["child_processes"].append(child)

    except FileNotFoundError as e:
        result["error"] = f"Interpreter not found: {e}"
    except PermissionError as e:
        result["error"] = f"Permission denied executing file: {e}"
    except Exception as e:
        logger.error(f"[dynamic] Unexpected error: {e}", exc_info=True)
        result["error"] = f"Dynamic analysis failed: {str(e)}"
    finally:
        # ── 6. Stop filesystem monitor ────────────────────────────────────
        if observer:
            observer.stop()
            observer.join(timeout=3)
        result["filesystem_events"] = fs_collector.snapshot() if _WATCHDOG_AVAILABLE else []

    # ── 7. Score risk ──────────────────────────────────────────────────────
    result["risk"] = _score_risk(result)

    logger.info(
        f"[dynamic] Done — verdict={result['risk'].get('verdict')} "
        f"score={result['risk'].get('risk_score')} "
        f"timed_out={result['timed_out']}"
    )
    return result