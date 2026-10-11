"""Bounded ClamAV daemon client for in-memory attachment scanning.

The adapter speaks clamd's INSTREAM protocol and never writes the attachment
to disk. Configure it only for a trusted local socket or private service
network; clamd's TCP protocol is not encrypted or authenticated.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Any


_CHUNK_SIZE = 64 * 1024
_MAX_RESPONSE_BYTES = 4096


def is_configured() -> bool:
    return bool(
        os.getenv("MAILTRACE_CLAMD_UNIX_SOCKET", "").strip()
        or os.getenv("MAILTRACE_CLAMD_HOST", "").strip()
    )


def _timeout_seconds() -> float:
    try:
        value = float(os.getenv("MAILTRACE_CLAMD_TIMEOUT_SECONDS", "2.0"))
    except (TypeError, ValueError):
        value = 2.0
    return min(5.0, max(0.1, value))


def _connect(deadline: float | None = None) -> tuple[socket.socket | None, str | None]:
    unix_path = os.getenv("MAILTRACE_CLAMD_UNIX_SOCKET", "").strip()
    if unix_path:
        if not hasattr(socket, "AF_UNIX"):
            return None, "UNIX_SOCKET_UNSUPPORTED"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        address: Any = unix_path
    else:
        host = os.getenv("MAILTRACE_CLAMD_HOST", "").strip()
        if not host:
            return None, None
        try:
            port = int(os.getenv("MAILTRACE_CLAMD_PORT", "3310"))
        except ValueError:
            return None, "INVALID_CONFIGURATION"
        if not 1 <= port <= 65535:
            return None, "INVALID_CONFIGURATION"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (host, port)
    remaining = deadline - time.monotonic() if deadline is not None else _timeout_seconds()
    if remaining <= 0:
        sock.close()
        return None, "TIME_BUDGET_EXCEEDED"
    sock.settimeout(min(_timeout_seconds(), remaining))
    try:
        sock.connect(address)
        return sock, None
    except (OSError, socket.timeout) as error:
        sock.close()
        return None, type(error).__name__.upper()


def scan_attachment(payload: bytes, *, deadline: float | None = None) -> dict[str, Any]:
    """Return a conservative ClamAV result for one bounded in-memory payload."""
    if not isinstance(payload, bytes):
        return {"status": "ERROR", "malware_confirmed": None, "engine": "ClamAV", "error_type": "INVALID_PAYLOAD"}
    try:
        sock, connection_error = _connect(deadline)
    except OSError as error:
        return {"status": "ERROR", "malware_confirmed": None, "engine": "ClamAV", "error_type": type(error).__name__.upper()}
    if sock is None:
        if connection_error is None:
            return {
                "status": "NOT_CONFIGURED",
                "malware_confirmed": None,
                "reason": "ClamAV scanning is not configured.",
            }
        if connection_error == "TIME_BUDGET_EXCEEDED":
            return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
        return {"status": "ERROR", "malware_confirmed": None, "engine": "ClamAV", "error_type": connection_error}

    try:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
            sock.settimeout(min(_timeout_seconds(), remaining))
        sock.sendall(b"zINSTREAM\0")
        for offset in range(0, len(payload), _CHUNK_SIZE):
            if deadline is not None and time.monotonic() >= deadline:
                return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
            chunk = payload[offset : offset + _CHUNK_SIZE]
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
                sock.settimeout(min(_timeout_seconds(), remaining))
            sock.sendall(struct.pack("!I", len(chunk)))
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
                sock.settimeout(min(_timeout_seconds(), remaining))
            sock.sendall(chunk)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
            sock.settimeout(min(_timeout_seconds(), remaining))
        sock.sendall(struct.pack("!I", 0))

        response = bytearray()
        while len(response) < _MAX_RESPONSE_BYTES:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"status": "TIME_BUDGET_EXCEEDED", "malware_confirmed": None, "engine": "ClamAV"}
                sock.settimeout(min(_timeout_seconds(), remaining))
            chunk = sock.recv(min(512, _MAX_RESPONSE_BYTES - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if b"\n" in chunk:
                break

        line = bytes(response).split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
        if line.endswith(": OK"):
            return {"status": "CLEAN", "malware_confirmed": False, "engine": "ClamAV"}
        if line.endswith(" FOUND"):
            signature = line.rsplit(":", 1)[-1].removesuffix(" FOUND").strip()[:200]
            return {
                "status": "INFECTED",
                "malware_confirmed": True,
                "engine": "ClamAV",
                "signature": signature,
            }
        return {"status": "ERROR", "malware_confirmed": None, "engine": "ClamAV", "error_type": "SCANNER_RESPONSE_INVALID"}
    except (OSError, socket.timeout) as error:
        return {"status": "ERROR", "malware_confirmed": None, "engine": "ClamAV", "error_type": type(error).__name__.upper()}
    finally:
        sock.close()


def health_status() -> str:
    """Probe clamd with a short PING and return a non-sensitive readiness state."""
    if not is_configured():
        return "NOT_CONFIGURED"
    deadline = time.monotonic() + 0.75
    try:
        sock, error = _connect(deadline)
        if sock is None:
            return "UNAVAILABLE"
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            sock.sendall(b"zPING\0")
            response = sock.recv(128).strip()
            return "READY" if response in {b"PONG", b"PONG\0"} else "UNAVAILABLE"
        finally:
            sock.close()
    except (OSError, socket.timeout):
        return "UNAVAILABLE"
