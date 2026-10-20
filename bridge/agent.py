import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP_ROOT = Path(os.environ.get(
    "MAILTRACE_PROJECT_ROOT",
    r"C:\Users\ritur\New folder\mailtrace\MailTrace-AI"
)).resolve()

LOG_DIR = APP_ROOT / ".mailtrace_bridge"
LOG_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_LOG = LOG_DIR / "audit.jsonl"

TOKEN = os.environ.get("MAILTRACE_BRIDGE_TOKEN", "CHANGE-ME")

ALLOWED = {
    "status": ["git", "status"],
    "pytest": ["python", "-m", "pytest"],
    "py_compile": ["python", "-m", "py_compile"],
    "python_version": ["python", "--version"],
}

app = FastAPI(title="MailTrace PowerShell Bridge", version="1.0.0")


class RunRequest(BaseModel):
    action: str = Field(..., min_length=1)
    args: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=120, ge=1, le=300)


def audit(record):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **record,
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def resolve_python():
    venv_python = APP_ROOT / "backend" / "venv" / "Scripts" / "python.exe"
    return str(venv_python) if venv_python.exists() else "python"


def build_command(req: RunRequest):
    if req.action not in ALLOWED:
        raise HTTPException(403, "Action is not allowlisted.")

    base = ALLOWED[req.action].copy()

    if req.action == "pytest":
        base[0] = resolve_python()
        # Only permit pytest paths/options that don't invoke another shell.
        for arg in req.args:
            if any(x in arg for x in ["&", "|", ";", ">", "<", "`", "$(", "\x00"]):
                raise HTTPException(400, "Unsafe argument.")
        if not req.args:
            base += ["backend/tests"]
        else:
            base += req.args
    elif req.action == "py_compile":
        base[0] = resolve_python()
        if not req.args:
            raise HTTPException(400, "py_compile requires at least one .py file.")
        for arg in req.args:
            p = (APP_ROOT / arg).resolve()
            if APP_ROOT not in p.parents and p != APP_ROOT:
                raise HTTPException(400, "Path is outside project root.")
            if p.suffix.lower() != ".py":
                raise HTTPException(400, "Only .py files may be compiled.")
        base += req.args
    elif req.args:
        raise HTTPException(400, f"Arguments are not supported for {req.action}.")

    return base


@app.get("/health")
def health():
    return {"ok": True, "project_root": str(APP_ROOT)}


@app.post("/run")
def run(req: RunRequest, x_bridge_token: str | None = Header(default=None)):
    if not x_bridge_token or x_bridge_token != TOKEN:
        raise HTTPException(401, "Invalid bridge token.")

    command = build_command(req)
    started = time.time()

    audit({
        "event": "command_started",
        "action": req.action,
        "command": command,
    })

    try:
        completed = subprocess.run(
            command,
            cwd=str(APP_ROOT),
            capture_output=True,
            text=True,
            timeout=req.timeout_seconds,
            shell=False,
            env=os.environ.copy(),
        )
        result = {
            "ok": completed.returncode == 0,
            "action": req.action,
            "command": command,
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "duration_seconds": round(time.time() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "ok": False,
            "action": req.action,
            "command": command,
            "exit_code": None,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or "") + "\nCommand timed out.",
            "duration_seconds": round(time.time() - started, 3),
        }

    audit({"event": "command_finished", **result})
    return result
