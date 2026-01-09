#!/usr/bin/env python3
"""
common.py — shared helpers for orchestrator, mapping, and report generation.
"""

import os
import json
import subprocess
from datetime import datetime

WORK_DIR = "./oran_orchestrator_work"

def ensure_work_dir():
    """Ensure work directory exists and return its path."""
    os.makedirs(WORK_DIR, exist_ok=True)
    return WORK_DIR

def now_ts():
    """Return ISO8601 timestamp string (UTC)."""
    return datetime.utcnow().isoformat() + "Z"

def load_json_if_exists(path):
    """Load JSON from file if exists, else return None."""
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None
    return None

def write_json(path, obj):
    """Safely write JSON object to a file."""
    try:
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)
        return True
    except Exception as e:
        print(f"[WARN] Failed to write {path}: {e}")
        return False

def run_cmd_capture(cmd, timeout=10):
    """
    Run shell command and capture stdout/stderr.
    Returns (rc, stdout, stderr).
    """
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return -1, "", str(e)

def is_oran_process(name, cmdline=""):
    """
    Heuristic: return True if process is relevant to O-RAN / 5G Core / UE / gNB.
    """
    if not name:
        return False
    lname = name.lower()
    lcmd = (cmdline or "").lower()
    keywords = [
        "open5gs", "nr-softmodem", "ue-softmodem", "gnb", "amfd", "smfd", "upfd",
        "hssd", "ausfd", "pcfd", "pcrfd", "nssfd", "udrd", "scp", "mongodb",
        "iperf3", "ric", "flexric"
    ]
    return any(k in lname or k in lcmd for k in keywords)

