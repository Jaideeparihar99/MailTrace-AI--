# MailTrace — Regional SOC Routing v1

This package adds the first production-oriented SOC routing layer without replacing the existing case claim/lease system.

## What it adds

- Tenant-scoped SOC queues with a configured `region_key`.
- Employee-to-region configuration based on organizational identity, **not IP geolocation**.
- Automatic routing when an employee report creates/updates a case.
- High-risk gateway alerts can use the signed SMTP envelope recipient to resolve an admin-configured employee region.
- Central SOC fallback when no active regional mapping/queue exists.
- Capacity-aware analyst selection using `max_open_cases` and current open case load.
- Persistent routing records and routing audit events.
- Admin endpoints for queue, employee-region and analyst configuration.
- SOC endpoint to inspect a case's routing record.
- Existing `/api/cases/{case_id}/claim` and 20-minute analyst claim lease remain intact.

## Files in this feature package

- `backend/database/database.py` — new routing tables and routing functions.
- `backend/main.py` — initializes routing, registers the router, and routes employee-report cases.
- `backend/services/case_routing.py` — service wrapper.
- `backend/routes/soc_routing.py` — configuration and routing APIs.
- `backend/tests/test_soc_routing.py` — isolated SQLite routing/fallback test.

## PowerShell install

From the MailTrace project root, back up the two modified files first:

```powershell
Copy-Item .\backend\main.py .\backend\main.py.before-soc-routing-v1 -Force
Copy-Item .\backend\database\database.py .\backend\database\database.py.before-soc-routing-v1 -Force
```

Then copy the package files into the project, preserving the `backend\` paths.

## Configuration flow

1. Create a regional queue with `POST /api/soc/routing/queues`.
2. Map an employee `subject_id` to that region with `PUT /api/soc/routing/employee-regions/{subject_id}`. Include `email_address` when gateway detections must be routed by signed SMTP recipient, for example:

   ```json
   {
     "region_key": "NORTH",
     "team_key": "BANKING",
     "email_address": "employee@bank.example",
     "active": true,
     "reason": "Verified employee branch assignment"
   }
   ```

   Set `MAILTRACE_ROUTING_EMAIL_HMAC_KEY` to a private value of at least 32 characters before configuring email mappings. MailTrace stores only a keyed HMAC of the normalized address, not the address itself. The address-to-region mapping is tenant-scoped and admin-managed. Automatic routing uses it only when the signed SMTP envelope has exactly one recipient and the address resolves to exactly one active identity. Multiple recipients, duplicate active mappings, or an unmapped address go to Central SOC; the message's untrusted `To` header is never used for regional routing. Keep the HMAC key stable; changing it requires re-saving employee mappings.
3. Register available analysts for that region with `PUT /api/soc/routing/analysts/{subject_id}`.
4. Employee report cases route using the authenticated reporter `subject_id`; gateway auto-alert cases may route using the signed envelope recipient above.
5. The case is assigned to the matching regional queue and, if capacity is available, to the least-loaded eligible analyst.
6. If regional mapping/queue is unavailable, the case goes to the tenant's `CENTRAL` queue.
7. Existing analyst claim/lease remains the final working lock for investigation work.
8. Automated reconciliation preserves an existing analyst assignment; only the explicit SOC-lead reroute action recalculates ownership. This prevents concurrent queue refreshes or duplicate reports from silently moving an analyst's case.

## Important boundary

Current implementation boundaries (October 2026): OIDC authentication and SLA timers/escalation are present, and the gateway webhook now returns allow/review/quarantine policy decisions with signed action receipts. These interfaces do not, by themselves, connect to an institution's identity provider or email gateway or prove that a gateway action was applied. An institution must configure and validate its own adapter. Production startup deliberately supports one tenant until all legacy and file-backed stores are tenant-scoped. Employee report status is available, but a complete administrator-managed SSO lifecycle, multi-tenant data isolation, and end-to-end gateway vendor integration still require production integration work.

## Verification performed before delivery

- Python syntax compilation for all changed Python files: PASS.
- Backend `main` module import: PASS.
- Isolated SQLite regional routing test: PASS.
- Isolated SQLite central fallback test: PASS.
