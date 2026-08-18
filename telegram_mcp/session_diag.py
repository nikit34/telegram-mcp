"""Diagnostics for Telegram session lifetime.

Telegram revokes an auth key with ``AuthKeyDuplicatedError`` when the same
StringSession is seen from two source IPs at once. The regular error log only
records the moment the key is already dead, which is too late to tell *what*
was holding it. This module records the facts needed to answer that:

- which process is using which session (fingerprint, pid, parent command),
- whether another live process already holds the same session,
- the local socket address every connection egresses from, so a VPN route
  change shows up as a different source IP on the same session,
- every connect, disconnect and forced reconnect, with the reason.

Output goes to ``session_debug.log`` next to ``mcp_errors.log`` as one JSON
object per line. Set ``TELEGRAM_SESSION_DEBUG=0`` to turn it off.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from pythonjsonlogger import jsonlogger

_PACKAGE_DIR = Path(__file__).resolve().parent
_REPO_DIR = _PACKAGE_DIR.parent
_LOG_PATH = _REPO_DIR / "session_debug.log"
_REGISTRY_PATH = _REPO_DIR / "session_instances.json"

_ENABLED = os.getenv("TELEGRAM_SESSION_DEBUG", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

logger = logging.getLogger("telegram_mcp.session")


def _setup() -> None:
    """Attach a JSON file handler once; stay silent if the file is unwritable."""
    if logger.handlers or not _ENABLED:
        return
    logger.setLevel(logging.INFO)
    # Errors already have their own sink; this log must not duplicate into it.
    logger.propagate = False
    try:
        handler = logging.FileHandler(_LOG_PATH, mode="a")
    except Exception as exc:  # pragma: no cover - depends on the filesystem
        print(f"WARNING: session diagnostics disabled: {exc}", file=sys.stderr)
        return
    handler.setFormatter(
        jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger.addHandler(handler)


_setup()


def fingerprint(session_string: str | None) -> str:
    """Stable short id for a session string, safe to write to a log."""
    if not session_string:
        return "none"
    return hashlib.sha256(session_string.encode()).hexdigest()[:12]


def _parent_command() -> str:
    """Command line of the parent process, to tell Claude Code from a shell."""
    try:
        out = subprocess.run(
            ["ps", "-o", "command=", "-p", str(os.getppid())],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return out.stdout.strip()[:300]
    except Exception:
        return ""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False
    return True


def register_instance(fingerprints: dict[str, str]) -> list[dict[str, Any]]:
    """Record this process in the registry and return live rivals.

    A rival is another running process registered against one of the same
    session fingerprints - the exact condition Telegram punishes. Dead pids are
    pruned on every call, so the file cannot grow without bound.
    """
    if not _ENABLED:
        return []

    entry = {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "started_at": time.time(),
        "argv": " ".join(sys.argv)[:300],
        "parent_command": _parent_command(),
        "fingerprints": fingerprints,
    }

    try:
        existing = json.loads(_REGISTRY_PATH.read_text())
        if not isinstance(existing, list):
            existing = []
    except Exception:
        existing = []

    alive = [
        row
        for row in existing
        if isinstance(row, dict)
        and row.get("pid") != entry["pid"]
        and _pid_alive(int(row.get("pid", -1)))
    ]

    mine = set(fingerprints.values())
    rivals = [row for row in alive if mine & set((row.get("fingerprints") or {}).values())]

    try:
        _REGISTRY_PATH.write_text(json.dumps(alive + [entry], indent=2))
    except Exception:
        pass

    return rivals


def socket_addresses(client: Any) -> dict[str, Any]:
    """Local and remote address of the client's live TCP connection.

    The local address is the point of this whole module: two processes on the
    same host egressing through different routes (a VPN interface and the
    default one) are what produce a duplicated auth key.
    """
    info: dict[str, Any] = {"sockname": None, "peername": None}
    try:
        connection = client._sender._connection  # noqa: SLF001 - telethon internals
    except Exception:
        return info

    writer = None
    for attr in ("_writer", "_stream_writer"):
        writer = getattr(connection, attr, None)
        if writer is not None:
            break
    if writer is None:
        stream = getattr(connection, "_stream", None)
        writer = getattr(stream, "_writer", None) if stream is not None else None
    if writer is None:
        return info

    for key in ("sockname", "peername"):
        try:
            value = writer.get_extra_info(key)
        except Exception:
            value = None
        if isinstance(value, (tuple, list)):
            value = ":".join(str(part) for part in value[:2])
        info[key] = value
    return info


def client_facts(client: Any) -> dict[str, Any]:
    """Identity of the session behind a client: auth key, datacenter, addresses."""
    facts: dict[str, Any] = {}
    session = getattr(client, "session", None)
    if session is not None:
        facts["dc_id"] = getattr(session, "dc_id", None)
        facts["server_address"] = getattr(session, "server_address", None)
        auth_key = getattr(session, "auth_key", None)
        key_id = getattr(auth_key, "key_id", None) if auth_key is not None else None
        facts["auth_key_id"] = str(key_id) if key_id is not None else None
    # Deliberately no is_connected() call here: this runs inside connection
    # bookkeeping, and probing the client would change the behaviour it observes.
    # A present sockname already means the socket is up.
    facts.update(socket_addresses(client))
    return facts


def event(name: str, **fields: Any) -> None:
    """Write one diagnostic line. Never raises."""
    if not _ENABLED:
        return
    try:
        logger.info(name, extra={"pid": os.getpid(), **fields})
    except Exception:
        pass
