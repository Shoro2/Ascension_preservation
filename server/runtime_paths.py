"""Paths for an installed preservation runtime, separate from source and fixtures.

ASC_CONFIG may name a private JSON file; otherwise runtime.local.json beside
this module is read. Explicit environment variables override the file. Existing
installations can point state_dir at their old state directory without moving it.
"""
import json
import os
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("ASC_CONFIG") or SOURCE / "runtime.local.json")
CONFIG = {}
if CONFIG_PATH.is_file():
    CONFIG = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    if not isinstance(CONFIG, dict):
        raise ValueError("Preservation runtime configuration must be a JSON object")
DEFAULT_RUNTIME = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "AscensionPreservation"

def path(key, env, default):
    value = os.environ.get(env) or CONFIG.get(key)
    result = Path(value) if value else Path(default)
    if not result.is_absolute():
        result = CONFIG_PATH.parent / result
    return str(result.resolve())

RUNTIME = path("runtime_dir", "ASC_RUNTIME_DIR", DEFAULT_RUNTIME)
STATE = path("state_dir", "ASC_DATA_DIR", Path(RUNTIME) / "state")
LOGS = path("log_dir", "ASC_LOG_DIR", Path(RUNTIME) / "logs")

def state_dir():
    Path(STATE).mkdir(parents=True, exist_ok=True)
    return STATE

def log_file(name):
    Path(LOGS).mkdir(parents=True, exist_ok=True)
    return str(Path(LOGS) / name)
