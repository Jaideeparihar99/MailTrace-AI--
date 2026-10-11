"""Provision the explicitly local-only Churu MailTrace intake queue.

This does not create a staffed SOC, contact a government agency, or dispatch
notifications outside MailTrace. It is intentionally blocked in production.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import database.database as db  # noqa: E402

QUEUE_CONFIGURATION: dict[str, Any] = {
    "tenant_id": "local",
    "queue_id": "CHURU-SOC",
    "name": "Churu Regional SOC Intake (local MailTrace queue only)",
    "region_key": "CHURU",
    "team_key": "DISTRICT-SOC",
    "is_central": False,
    "active": True,
}
REASON = (
    "User-requested reported-location intake for Taranagar, Churu, Rajasthan. "
    "Local MailTrace queue placeholder only; no verified external SOC endpoint "
    "or staffed regional analyst roster is configured."
)


def configure_queue(*, apply: bool, tenant_id: str = "local", database_module=db) -> dict[str, Any]:
    """Preview or idempotently upsert the local queue; never seeds real identities."""
    if tenant_id != "local":
        raise ValueError("This bootstrap is local-development only; tenant_id must be 'local'.")
    if database_module.is_production():
        raise RuntimeError("Refusing to provision a local-only SOC queue in production mode.")

    preview = {**QUEUE_CONFIGURATION, "reason": REASON, "external_dispatch": "NOT_CONFIGURED", "regional_analysts": "NOT_CONFIGURED"}
    if not apply:
        return {"applied": False, "preview": preview}

    database_module.initialize_database()
    database_module.initialize_soc_routing()
    queue = database_module.configure_soc_queue(
        tenant_id,
        QUEUE_CONFIGURATION["queue_id"],
        QUEUE_CONFIGURATION["name"],
        QUEUE_CONFIGURATION["region_key"],
        team_key=QUEUE_CONFIGURATION["team_key"],
        is_central=False,
        active=True,
        actor_subject="system:local-churu-intake-bootstrap",
        reason=REASON,
    )
    return {
        "applied": True,
        "queue": queue,
        "external_dispatch": "NOT_CONFIGURED",
        "regional_analysts": "NOT_CONFIGURED",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", default="local", help="Must be 'local'; production tenants are deliberately rejected.")
    parser.add_argument("--apply", action="store_true", help="Persist the queue configuration. Without this flag only preview it.")
    args = parser.parse_args()
    try:
        result = configure_queue(apply=args.apply, tenant_id=args.tenant_id)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    if not args.apply:
        print("DRY RUN ONLY: pass --apply to persist this local-only queue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
