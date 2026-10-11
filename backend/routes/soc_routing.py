from typing import Optional
import re
import logging

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from database.database import (
    assign_case_manually,
    allow_soc_action,
    configure_employee_region,
    configure_soc_analyst,
    configure_soc_queue,
    get_case_routing,
    get_case_routing_events,
    get_connection,
    get_soc_queue,
    get_pending_cases_for_routing,
    process_sla_escalations,
    route_case_to_soc,
)
from services.access_control import is_production

router = APIRouter(prefix="/api/soc/routing", tags=["SOC Routing"])
_LEAD_ROLES = {"soc_lead", "tenant_admin", "platform_admin", "admin"}
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,62}$")
_logger = logging.getLogger("mailtrace.soc_routing")


def _principal(request: Request, *, lead: bool = False):
    principal = getattr(request.state, "principal", None)
    if principal is None or not principal.subject_id or not principal.tenant_id:
        raise HTTPException(status_code=401, detail="Verified analyst identity is required.")
    if is_production() and getattr(principal, "auth_method", "api_key") != "oidc":
        raise HTTPException(status_code=403, detail="Production SOC routing requires a verified OIDC identity.")
    roles = set(principal.roles)
    if not roles.intersection(_LEAD_ROLES if lead else (_LEAD_ROLES | {"analyst"})):
        raise HTTPException(status_code=403, detail="SOC analyst or authorized SOC lead role required.")
    return principal


def _rate_limit(principal, action: str, limit: int = 30):
    if not allow_soc_action(principal.tenant_id, principal.subject_id, action, limit=limit, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many SOC routing actions; retry shortly.", headers={"Retry-After": "60"})


def _validate_key(value: str, label: str) -> str:
    value = str(value or "").strip()
    if not _KEY.fullmatch(value):
        raise HTTPException(status_code=422, detail=f"{label} has an invalid format.")
    return value


class QueueConfig(BaseModel):
    queue_id: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=2, max_length=100)
    region_key: str = Field(min_length=2, max_length=63)
    team_key: str = Field(default="", max_length=63)
    is_central: bool = False
    active: bool = True
    reason: str = Field(min_length=5, max_length=300)


class EmployeeRegionConfig(BaseModel):
    region_key: str = Field(min_length=2, max_length=63)
    team_key: str = Field(default="", max_length=63)
    email_address: Optional[str] = Field(default=None, max_length=320)
    active: bool = True
    reason: str = Field(min_length=5, max_length=300)


class AnalystConfig(BaseModel):
    region_key: str = Field(min_length=2, max_length=63)
    team_key: str = Field(default="", max_length=63)
    skills: list[str] = Field(default_factory=list, max_length=50)
    availability: str = "AVAILABLE"
    max_open_cases: int = Field(default=20, ge=1, le=1000)
    active: bool = True
    reason: str = Field(min_length=5, max_length=300)


class ManualAssignment(BaseModel):
    analyst_subject: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=5, max_length=300)


@router.get("/queue")
def read_soc_queue(
    request: Request,
    region_key: Optional[str] = Query(default=None, max_length=63),
    limit: int = Query(default=200, ge=1, le=500),
):
    principal = _principal(request)
    # Reconcile missing route records before rendering; failed routes remain visible
    # in logs and are retried on the next queue refresh/worker pass.
    routing_pending = 0
    for pending in get_pending_cases_for_routing(principal.tenant_id, min(limit, 100)):
        incident_type = str(pending.get("incident_type") or "")
        required_skills = {
            "suspicious": ["phishing"],
            "clicked_link": ["phishing", "url-analysis"],
            "opened_attachment": ["malware-analysis"],
            "shared_credentials": ["bec", "incident-response"],
            "made_payment": ["bec", "incident-response"],
        }.get(incident_type, ["phishing"] if str(pending.get("severity", "")).upper() in {"HIGH", "CRITICAL"} else [])
        try:
            route_case_to_soc(
                pending["case_id"], principal.tenant_id, str(pending.get("reporter_subject") or ""),
                actor_subject=principal.subject_id, required_skills=required_skills,
            )
        except Exception:
            routing_pending += 1
            _logger.exception("soc_case_route_pending tenant_id=%s case_id=%s", principal.tenant_id, pending["case_id"])
    escalated = process_sla_escalations(principal.tenant_id)
    cases = get_soc_queue(principal.tenant_id, region_key, limit)
    return {
        "success": True,
        "count": len(cases),
        "unassigned_count": sum(1 for case in cases if not case.get("assigned_analyst")),
        "overdue_count": sum(1 for case in cases if case.get("overdue")),
        "escalations_created": escalated,
        "routing_pending_count": routing_pending,
        "cases": cases,
    }


@router.get("/alerts")
def read_sla_alerts(request: Request, status: Optional[str] = Query(default="OPEN", max_length=20), limit: int = Query(default=100, ge=1, le=500)):
    """Return tenant-scoped, durable SLA escalation alerts for SOC triage."""
    principal = _principal(request)
    normalized_status = str(status or "").strip().upper()
    if normalized_status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED", "ALL"}:
        raise HTTPException(status_code=422, detail="status must be OPEN, ACKNOWLEDGED, RESOLVED, or ALL.")
    connection = get_connection()
    try:
        query = """SELECT a.id AS alert_id, a.tenant_id, a.case_id, c.title, c.severity, a.alert_type, a.priority,
                         a.sla_deadline, a.assigned_analyst, a.routing_status, a.escalation_count,
                         a.status, a.first_seen_at, a.last_seen_at,
                         CASE WHEN datetime(a.sla_deadline)<=datetime('now') THEN 1 ELSE 0 END AS overdue
                  FROM soc_sla_alerts a JOIN cases c ON c.case_id=a.case_id AND c.tenant_id=a.tenant_id
                  WHERE a.tenant_id=?"""
        params = [principal.tenant_id]
        if normalized_status != "ALL":
            query += " AND a.status=?"
            params.append(normalized_status)
        query += " ORDER BY CASE a.priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END, a.last_seen_at DESC LIMIT ?"
        params.append(limit)
        rows = connection.execute(query, params).fetchall()
        return {"success": True, "count": len(rows), "alerts": [dict(row) for row in rows]}
    finally:
        connection.close()


def _transition_sla_alert(alert_id: int, request: Request, target_status: str):
    principal = _principal(request)
    _rate_limit(principal, "sla_alert_" + target_status.lower())
    allowed_from = "OPEN" if target_status == "ACKNOWLEDGED" else "ACKNOWLEDGED"
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        alert = connection.execute(
            "SELECT id, tenant_id, case_id, status FROM soc_sla_alerts WHERE id=? AND tenant_id=?",
            (alert_id, principal.tenant_id),
        ).fetchone()
        if alert is None:
            connection.rollback()
            raise HTTPException(status_code=404, detail="SLA alert not found.")
        current = str(alert["status"] or "").upper()
        if current != allowed_from:
            connection.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"Cannot transition SLA alert from {current or 'UNKNOWN'} to {target_status}; expected {allowed_from}.",
            )
        updated = connection.execute(
            "UPDATE soc_sla_alerts SET status=?, last_seen_at=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=? AND status=?",
            (target_status, alert_id, principal.tenant_id, allowed_from),
        ).rowcount
        if updated != 1:
            connection.rollback()
            raise HTTPException(status_code=409, detail="SLA alert changed concurrently; refresh and retry.")
        connection.execute(
            "INSERT INTO soc_sla_alert_events(alert_id, tenant_id, case_id, actor_subject, action, from_status, to_status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (alert_id, principal.tenant_id, alert["case_id"], principal.subject_id, target_status, allowed_from, target_status),
        )
        connection.commit()
        return {
            "success": True,
            "alert_id": alert_id,
            "case_id": alert["case_id"],
            "status": target_status,
            "actor_subject": principal.subject_id,
        }
    except HTTPException:
        raise
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_sla_alert(alert_id: int, request: Request):
    """Acknowledge an open SLA alert and persist an actor/time audit event."""
    return _transition_sla_alert(alert_id, request, "ACKNOWLEDGED")


@router.post("/alerts/{alert_id}/resolve")
def resolve_sla_alert(alert_id: int, request: Request):
    """Resolve an acknowledged SLA alert and persist an actor/time audit event."""
    return _transition_sla_alert(alert_id, request, "RESOLVED")


@router.get("/analysts")
def read_analyst_roster(request: Request):
    principal = _principal(request, lead=True)
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT a.subject_id, a.region_key, a.team_key, a.skills_json, a.availability,
                   a.active, a.max_open_cases,
                   (SELECT COUNT(*) FROM case_routing r JOIN cases c
                      ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
                    WHERE r.tenant_id=a.tenant_id AND r.assigned_analyst=a.subject_id
                      AND r.status IN ('ASSIGNED','IN_PROGRESS')
                      AND UPPER(COALESCE(c.status,'OPEN')) NOT IN ('CLOSED','RESOLVED')) AS open_load
            FROM soc_analysts a WHERE a.tenant_id=? ORDER BY a.active DESC, a.availability, a.region_key, a.subject_id
        """, (principal.tenant_id,)).fetchall()
        analysts = []
        import json
        for row in rows:
            item = dict(row)
            try:
                item["skills"] = json.loads(item.pop("skills_json") or "[]")
            except (TypeError, json.JSONDecodeError):
                item["skills"] = []
            analysts.append(item)
        return {"success": True, "analysts": analysts}
    finally:
        connection.close()


@router.get("/cases/{case_id}")
def read_case_routing(case_id: str, request: Request):
    principal = _principal(request)
    connection = get_connection()
    try:
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id=? AND tenant_id=?",
            (case_id, principal.tenant_id),
        ).fetchone()
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found.")
    finally:
        connection.close()
    routing = get_case_routing(case_id, principal.tenant_id)
    if routing is None:
        raise HTTPException(status_code=404, detail="Case has not been routed yet.")
    return {"success": True, "routing": routing}


@router.get("/cases/{case_id}/history")
def read_routing_history(case_id: str, request: Request):
    principal = _principal(request)
    connection = get_connection()
    try:
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id=? AND tenant_id=?",
            (case_id, principal.tenant_id),
        ).fetchone()
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found.")
    finally:
        connection.close()
    return {"success": True, "events": get_case_routing_events(case_id, principal.tenant_id)}


@router.post("/queues")
def upsert_queue(payload: QueueConfig, request: Request):
    principal = _principal(request, lead=True)
    _rate_limit(principal, "soc_queue_config")
    queue_id = _validate_key(payload.queue_id, "queue_id").upper()
    region = _validate_key(payload.region_key, "region_key").upper()
    team = _validate_key(payload.team_key, "team_key").upper() if payload.team_key else ""
    try:
        queue = configure_soc_queue(
            principal.tenant_id, queue_id, payload.name.strip(), region,
            team_key=team, is_central=payload.is_central, active=payload.active,
            actor_subject=principal.subject_id, reason=payload.reason,
        )
    except Exception as error:
        raise HTTPException(status_code=409, detail="Queue configuration conflicts with an existing tenant queue.") from error
    return {"success": True, "queue": queue}


@router.put("/employee-regions/{subject_id}")
def set_employee_region(subject_id: str, payload: EmployeeRegionConfig, request: Request):
    principal = _principal(request, lead=True)
    _rate_limit(principal, "soc_employee_region_config")
    subject_id = str(subject_id).strip()
    if not subject_id or len(subject_id) > 128:
        raise HTTPException(status_code=422, detail="Employee subject ID is invalid.")
    region = _validate_key(payload.region_key, "region_key").upper()
    team = _validate_key(payload.team_key, "team_key").upper() if payload.team_key else ""
    email_address = str(payload.email_address or "").strip().casefold() or None
    if email_address and (
        not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", email_address)
        or any(ord(char) < 33 or ord(char) == 127 for char in email_address)
    ):
        raise HTTPException(status_code=422, detail="Employee email address is invalid.")
    try:
        mapping = configure_employee_region(
            principal.tenant_id, subject_id, region, team_key=team, email_address=email_address, active=payload.active,
            source="oidc_subject_admin_mapping", actor_subject=principal.subject_id, reason=payload.reason,
        )
    except ValueError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"success": True, "mapping": mapping}


@router.put("/analysts/{subject_id}")
def set_analyst(subject_id: str, payload: AnalystConfig, request: Request):
    principal = _principal(request, lead=True)
    _rate_limit(principal, "soc_analyst_config")
    subject_id = str(subject_id).strip()
    if not subject_id or len(subject_id) > 128:
        raise HTTPException(status_code=422, detail="Analyst subject ID is invalid.")
    region = _validate_key(payload.region_key, "region_key").upper()
    team = _validate_key(payload.team_key, "team_key").upper() if payload.team_key else ""
    try:
        analyst = configure_soc_analyst(
            principal.tenant_id, subject_id, region, team_key=team, skills=payload.skills,
            availability=payload.availability, max_open_cases=payload.max_open_cases,
            active=payload.active, actor_subject=principal.subject_id, reason=payload.reason,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"success": True, "analyst": analyst}


@router.post("/cases/{case_id}/assign")
def manual_assign(case_id: str, payload: ManualAssignment, request: Request):
    principal = _principal(request, lead=True)
    _rate_limit(principal, "soc_manual_assignment", limit=10)
    try:
        assignment = assign_case_manually(
            case_id, principal.tenant_id, payload.analyst_subject.strip(),
            principal.subject_id, payload.reason,
        )
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if assignment is None:
        raise HTTPException(status_code=404, detail="Case or active tenant analyst not found.")
    return {"success": True, "routing": assignment}


@router.post("/cases/{case_id}/route")
def reroute_case(case_id: str, request: Request):
    principal = _principal(request, lead=True)
    _rate_limit(principal, "soc_case_reroute", limit=10)
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT reporter_subject, incident_type FROM employee_email_reports WHERE case_id=? AND tenant_id=? ORDER BY created_at DESC LIMIT 1",
            (case_id, principal.tenant_id),
        ).fetchone()
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id=? AND tenant_id=?",
            (case_id, principal.tenant_id),
        ).fetchone()
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found.")
        reporter = row["reporter_subject"] if row else ""
        incident_type = row["incident_type"] if row else ""
    finally:
        connection.close()
    skills = {
        "suspicious": ["phishing"],
        "clicked_link": ["phishing", "url-analysis"],
        "opened_attachment": ["malware-analysis"],
        "shared_credentials": ["bec", "incident-response"],
        "made_payment": ["bec", "incident-response"],
    }.get(incident_type, ["phishing"])
    try:
        routing = route_case_to_soc(
            case_id,
            principal.tenant_id,
            reporter,
            actor_subject=principal.subject_id,
            required_skills=skills,
            force=True,
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Case not found for this tenant.") from error
    return {"success": True, "routing": routing}
