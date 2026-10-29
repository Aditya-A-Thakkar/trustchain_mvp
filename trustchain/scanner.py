"""Safe PickleScan adapter. Scans files without loading or executing pickle contents."""
from __future__ import annotations
from importlib.metadata import PackageNotFoundError, version as package_version
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

SUPPORTED = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".safetensors"}


def scan_picklescan(path: str | Path, timeout: int = 60) -> dict[str, Any]:
    target = Path(path).resolve()
    if not target.exists():
        return {"scanner": "picklescan", "status": "ERROR", "scanned_files": 0,
                "infected_files": 0, "suspicious_globals": 0, "dangerous_globals": 0,
                "error": "Path does not exist", "version": None}
    files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
    eligible = [p for p in files if p.suffix.lower() in SUPPORTED]
    exe = shutil.which("picklescan")
    if not eligible:
        return {"scanner": "picklescan", "status": "NOT_SCANNED", "scanned_files": 0,
                "infected_files": 0, "suspicious_globals": 0, "dangerous_globals": 0,
                "version": None, "error": "No supported model/pickle files found"}
    if not exe:
        return {"scanner": "picklescan", "status": "ERROR", "scanned_files": 0,
                "infected_files": 0, "suspicious_globals": 0, "dangerous_globals": 0,
                "version": None, "error": "picklescan executable not found in PATH"}
    try:
        try:
            version = package_version("picklescan")
        except PackageNotFoundError:
            version = "unknown"
        proc = subprocess.run([exe, "--path", str(target)], capture_output=True, text=True, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        def number(label: str) -> int | None:
            match = re.search(rf"{re.escape(label)}\s*:\s*(\d+)", output, re.I)
            return int(match.group(1)) if match else None
        scanned, infected = number("Scanned files"), number("Infected files")
        suspicious, dangerous = number("Suspicious globals"), number("Dangerous globals")
        if scanned is None or infected is None or suspicious is None or dangerous is None:
            status = "ERROR"
            error = "Could not parse scanner summary"
        elif scanned == 0:
            status, error = "NOT_SCANNED", "Scanner reported zero scanned files"
        elif proc.returncode != 0 and infected == 0 and suspicious == 0 and dangerous == 0:
            status, error = "ERROR", f"Scanner exited with status {proc.returncode}"
        elif infected > 0 or suspicious > 0 or dangerous > 0:
            status, error = "FINDINGS", None
        else:
            status, error = "CLEAN", None
        return {"scanner": "picklescan", "status": status, "scanned_files": scanned or 0,
                "infected_files": infected or 0, "suspicious_globals": suspicious or 0,
                "dangerous_globals": dangerous or 0, "version": version,
                "returncode": proc.returncode, "stdout": proc.stdout[-4000:],
                "stderr": proc.stderr[-2000:], "error": error}
    except subprocess.TimeoutExpired:
        return {"scanner": "picklescan", "status": "ERROR", "scanned_files": 0,
                "infected_files": 0, "suspicious_globals": 0, "dangerous_globals": 0,
                "version": None, "error": f"Scanner timed out after {timeout}s"}
    except Exception as exc:
        return {"scanner": "picklescan", "status": "ERROR", "scanned_files": 0,
                "infected_files": 0, "suspicious_globals": 0, "dangerous_globals": 0,
                "version": None, "error": str(exc)[:300]}
