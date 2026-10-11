from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
import uuid

from database.database import (
    get_connection,
    claim_case_for_analyst,
    renew_case_claim,
    release_case_claim,
    route_case_to_soc,
    get_case_routing,
    allow_soc_action,
    append_case_audit_event,
    verify_case_audit_chain,
    get_case_audit_events,
)
from services.access_control import is_production
from services.data_protection import protect_investigation_row
import logging

_case_logger = logging.getLogger("mailtrace.cases")


router = APIRouter(
    prefix="/api/cases",
    tags=["Cases"]
)


# ==========================================
# REQUEST MODELS
# ==========================================

class CreateCaseRequest(BaseModel):

    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "LOW"


class UpdateCaseRequest(BaseModel):

    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None


class AddNoteRequest(BaseModel):

    note: str
    # Kept for backward-compatible request parsing; server identity is authoritative.
    author: Optional[str] = None


class ClaimRequest(BaseModel):
    reason: Optional[str] = None


def _require_analyst_identity(request: Request):
    principal = getattr(request.state, "principal", None)
    if is_production() and getattr(principal, "auth_method", "api_key") != "oidc":
        raise HTTPException(
            status_code=403,
            detail="Production SOC case access requires a verified OIDC identity.",
        )
    if (
        principal is None
        or not principal.roles.intersection(
            {"analyst", "soc_lead", "tenant_admin", "platform_admin", "admin"}
        )
        or not principal.subject_id
    ):
        raise HTTPException(
            status_code=403,
            detail="A SOC analyst identity is required for case claiming.",
        )
    return principal


def _enforce_case_claim_owner(connection, case_id: str, request: Request):
    principal = _require_analyst_identity(request)
    case = connection.execute(
        "SELECT case_id FROM cases WHERE case_id=? AND tenant_id=?",
        (case_id, principal.tenant_id),
    ).fetchone()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    claim = connection.execute("""
        SELECT assigned_analyst, status, lease_expires_at,
               datetime(lease_expires_at) > datetime('now') AS lease_valid
        FROM case_claims
        WHERE case_id=? AND tenant_id=?
    """, (case_id, principal.tenant_id)).fetchone()
    if not claim or claim["status"] != "ACTIVE" or not claim["lease_valid"]:
        raise HTTPException(
            status_code=423,
            detail="An active case claim is required before modifying this case. Claim or reclaim it first.",
        )
    if principal.subject_id != claim["assigned_analyst"]:
        raise HTTPException(
            status_code=423,
            detail={
                "message": "Another analyst currently owns this case claim.",
                "assigned_analyst": claim["assigned_analyst"],
                "lease_expires_at": claim["lease_expires_at"],
            },
        )
    connection.execute(
        "UPDATE case_routing SET last_activity_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?",
        (case_id, principal.tenant_id),
    )


@router.post("/{case_id}/claim")
def claim_case(
    case_id: str,
    request: Request,
    payload: Optional[ClaimRequest] = None,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
):
    principal = _require_analyst_identity(request)
    if not allow_soc_action(principal.tenant_id, principal.subject_id, "case_claim"):
        raise HTTPException(status_code=429, detail="Too many case-claim actions; retry shortly.", headers={"Retry-After": "60"})
    try:
        assignment, claimed = claim_case_for_analyst(
            case_id=case_id,
            tenant_id=principal.tenant_id,
            analyst_subject=principal.subject_id,
            reason=(payload.reason if payload else None) or "claim requested",
            idempotency_key=idempotency_key,
        )
    except PermissionError as error:
        raise HTTPException(status_code=409, detail={"message": str(error)}) from error
    if assignment is None:
        raise HTTPException(status_code=404, detail="Case not found for this tenant.")
    if not claimed:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Case is currently claimed by another analyst.",
                "assignment": assignment,
            },
        )
    return {"success": True, "assignment": assignment}


@router.post("/{case_id}/renew")
def renew_case_claim_endpoint(
    case_id: str,
    request: Request,
    payload: Optional[ClaimRequest] = None,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
):
    principal = _require_analyst_identity(request)
    if not allow_soc_action(principal.tenant_id, principal.subject_id, "case_renew"):
        raise HTTPException(status_code=429, detail="Too many claim-renewal actions; retry shortly.", headers={"Retry-After": "60"})
    assignment, renewed = renew_case_claim(
        case_id=case_id,
        tenant_id=principal.tenant_id,
        analyst_subject=principal.subject_id,
        reason=(payload.reason if payload else None) or "renew requested",
        idempotency_key=idempotency_key,
    )
    if assignment is None:
        raise HTTPException(status_code=404, detail="Case has no claim in this tenant.")
    if not renewed:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Only the current owner with an unexpired claim can renew it.",
                "assignment": assignment,
            },
        )
    return {"success": True, "assignment": assignment}


@router.post("/{case_id}/release")
def release_case(
    case_id: str,
    request: Request,
    payload: Optional[ClaimRequest] = None,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
):
    principal = _require_analyst_identity(request)
    if not allow_soc_action(principal.tenant_id, principal.subject_id, "case_release"):
        raise HTTPException(status_code=429, detail="Too many claim-release actions; retry shortly.", headers={"Retry-After": "60"})
    assignment, released = release_case_claim(
        case_id=case_id,
        tenant_id=principal.tenant_id,
        analyst_subject=principal.subject_id,
        reason=(payload.reason if payload else None) or "release requested",
        idempotency_key=idempotency_key,
    )
    if assignment is None:
        raise HTTPException(status_code=404, detail="Case has no claim in this tenant.")
    if not released:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Only the current owner with an unexpired lease can release this claim.",
                "assignment": assignment,
            },
        )
    return {"success": True, "assignment": assignment}


@router.get("/{case_id}/history")
def case_claim_history(case_id: str, request: Request):
    principal = _require_analyst_identity(request)
    connection = get_connection()
    try:
        case = connection.execute(
            "SELECT 1 FROM cases WHERE case_id=? AND tenant_id=?",
            (case_id, principal.tenant_id),
        ).fetchone()
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found.")
        rows = connection.execute("""
            SELECT id, case_id, tenant_id, actor_subject, action, details_json, created_at
            FROM case_claim_events
            WHERE case_id=? AND tenant_id=?
            ORDER BY id ASC
        """, (case_id, principal.tenant_id)).fetchall()
        return {"success": True, "events": [dict(row) for row in rows]}
    finally:
        connection.close()


@router.get("/{case_id}/audit")
def case_audit_history(case_id: str, request: Request):
    """Return actor-attributed case changes and the tenant chain-integrity result."""
    principal = _require_analyst_identity(request)
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
    return {
        "success": True,
        "case_id": case_id,
        "events": get_case_audit_events(principal.tenant_id, case_id),
        "integrity": verify_case_audit_chain(principal.tenant_id),
    }


# ==========================================
# LIST CASES
# ==========================================

@router.get("")
def list_cases(request: Request):

    principal = _require_analyst_identity(request)
    connection = get_connection()

    try:

        rows = connection.execute("""
            SELECT
                cases.case_id,
                cases.title,
                cases.description,
                cases.severity,
                cases.status,
                cases.threat_score,
                cases.created_at,
                cases.updated_at,
                cc.assigned_analyst,
                cc.claimed_at,
                cc.lease_expires_at,
                cc.status AS assignment_status,
                CASE WHEN cc.status='ACTIVE' AND datetime(cc.lease_expires_at)<=datetime('now') THEN 1 ELSE 0 END AS claim_expired
            FROM cases
            LEFT JOIN case_claims cc
              ON cc.case_id=cases.case_id
             AND cc.tenant_id=?
             AND cc.status='ACTIVE'
            WHERE cases.tenant_id=?
              AND (cases.title NOT LIKE 'Automated % email review %'
               OR EXISTS (
                    SELECT 1
                    FROM email_alerts a
                    WHERE a.case_id = cases.case_id
                      AND a.recommended_action = 'QUARANTINE'
                      AND a.confidence = 'HIGH'
               ))
            ORDER BY cases.created_at DESC
        """, (principal.tenant_id, principal.tenant_id)).fetchall()

        return {
            "success": True,
            "count": len(rows),
            "cases": [dict(row) for row in rows]
        }

    finally:

        connection.close()


# ==========================================
# GET SINGLE CASE
# ==========================================

@router.get("/{case_id}")
def get_case(case_id: str, request: Request):

    principal = _require_analyst_identity(request)
    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT
                cases.case_id,
                cases.title,
                cases.description,
                cases.severity,
                cases.status,
                cases.threat_score,
                cases.created_at,
                cases.updated_at,
                cc.assigned_analyst,
                cc.claimed_at,
                cc.lease_expires_at,
                cc.status AS assignment_status,
                CASE WHEN cc.status='ACTIVE' AND datetime(cc.lease_expires_at)<=datetime('now') THEN 1 ELSE 0 END AS claim_expired
            FROM cases
            LEFT JOIN case_claims cc
              ON cc.case_id=cases.case_id
             AND cc.tenant_id=?
             AND cc.status='ACTIVE'
            WHERE cases.case_id = ?
              AND cases.tenant_id=?
              AND (
                    title NOT LIKE 'Automated % email review %'
                    OR EXISTS (
                        SELECT 1
                        FROM email_alerts a
                        WHERE a.case_id = cases.case_id
                          AND a.recommended_action = 'QUARANTINE'
                          AND a.confidence = 'HIGH'
                    )
              )
        """, (
            principal.tenant_id,
            case_id,
            principal.tenant_id,
        )).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        investigations = connection.execute("""
            SELECT
                ci.investigation_id,
                i.filename,
                i.subject,
                i.sender,
                i.recipient,
                i.threat_score,
                i.threat_verdict,
                i.threat_confidence,
                i.created_at
            FROM case_investigations ci
            JOIN investigations i
                ON i.investigation_id = ci.investigation_id
               AND i.tenant_id = ?
            WHERE ci.case_id = ?
            ORDER BY ci.created_at DESC
        """, (principal.tenant_id, case_id)).fetchall()

        notes = connection.execute("""
            SELECT
                id,
                note,
                author,
                created_at
            FROM case_notes
            WHERE case_id = ?
            ORDER BY created_at DESC
        """, (case_id,)).fetchall()

        evidence = connection.execute("""
            SELECT
                id,
                evidence_type,
                value,
                description,
                investigation_id,
                created_at
            FROM evidence
            WHERE case_id = ?
            ORDER BY created_at DESC
        """, (case_id,)).fetchall()

        case_payload = dict(case)
        principal = getattr(request.state, "principal", None)
        case_payload["assignment_mine"] = bool(
            principal
            and principal.subject_id
            and case_payload.get("assigned_analyst") == principal.subject_id
            and case_payload.get("assignment_status") == "ACTIVE"
            and not case_payload.get("claim_expired")
        )

        return {
            "success": True,
            "case": case_payload,
            "investigations": [protect_investigation_row(dict(row)) for row in investigations],
            "notes": [dict(row) for row in notes],
            "evidence": [dict(row) for row in evidence]
        }

    finally:

        connection.close()


# ==========================================
# CREATE CASE
# ==========================================

@router.post("")
def create_case(request: CreateCaseRequest, http_request: Request):

    principal = _require_analyst_identity(http_request)
    case_id = (
        "CASE-"
        + uuid.uuid4().hex[:10].upper()
    )

    severity = (
        request.severity or "LOW"
    ).upper()

    connection = get_connection()

    try:

        connection.execute("BEGIN IMMEDIATE")

        connection.execute("""
            INSERT INTO cases (
                case_id,
                tenant_id,
                title,
                description,
                severity,
                status,
                threat_score
            )
            VALUES (?, ?, ?, ?, ?, 'OPEN', 0)
        """, (
            case_id,
            principal.tenant_id,
            request.title,
            request.description or "",
            severity
        ))

        append_case_audit_event(
            connection,
            principal.tenant_id,
            case_id,
            principal.subject_id,
            "CASE_CREATED",
            to_status="OPEN",
            changed_fields=["title", "description", "severity", "status"],
        )

        connection.commit()

        routing = None
        try:
            routing = route_case_to_soc(
                case_id, principal.tenant_id, "", actor_subject=principal.subject_id,
                required_skills=["phishing"] if severity in {"HIGH", "CRITICAL"} else [],
            )
        except Exception:
            _case_logger.exception("case_routing_pending tenant_id=%s case_id=%s", principal.tenant_id, case_id)

        return {
            "success": True,
            "case": {
                "case_id": case_id,
                "title": request.title,
                "description": request.description or "",
                "severity": severity,
                "status": "OPEN",
                "threat_score": 0
            },
            "routing": routing,
            "routing_status": "ASSIGNED" if routing and routing.get("assigned_analyst") else "UNASSIGNED",
        }

    finally:

        connection.close()


# ==========================================
# UPDATE CASE
# ==========================================

@router.patch("/{case_id}")
def update_case(
    case_id: str,
    request: UpdateCaseRequest,
    http_request: Request,
):
    principal = _require_analyst_identity(http_request)

    connection = get_connection()

    try:

        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute("""
            SELECT case_id, title, description, severity, status
            FROM cases
            WHERE case_id = ? AND tenant_id = ?
        """, (case_id, principal.tenant_id)).fetchone()

        if existing is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        _enforce_case_claim_owner(connection, case_id, http_request)

        fields = []
        values = []
        changed_fields = []

        if request.title is not None:
            fields.append("title = ?")
            values.append(request.title)
            if request.title != existing["title"]:
                changed_fields.append("title")

        if request.description is not None:
            fields.append("description = ?")
            values.append(request.description)
            if request.description != existing["description"]:
                changed_fields.append("description")

        if request.severity is not None:
            fields.append("severity = ?")
            values.append(request.severity.upper())
            if request.severity.upper() != str(existing["severity"] or "").upper():
                changed_fields.append("severity")

        if request.status is not None:
            normalized_status = request.status.strip().upper().replace(" ", "_")
            if normalized_status not in {"OPEN", "IN_PROGRESS", "INVESTIGATING", "RESOLVED", "CLOSED"}:
                raise HTTPException(status_code=422, detail="Unsupported case status.")
            fields.append("status = ?")
            values.append(normalized_status)
            if normalized_status != str(existing["status"] or "OPEN").upper().replace(" ", "_"):
                changed_fields.append("status")

        if not fields:

            raise HTTPException(
                status_code=400,
                detail="No fields provided for update."
            )

        fields.append(
            "updated_at = CURRENT_TIMESTAMP"
        )

        values.extend([case_id, principal.tenant_id])

        connection.execute(
            f"""
            UPDATE cases
            SET {", ".join(fields)}
            WHERE case_id = ? AND tenant_id = ?
            """,
            values
        )

        append_case_audit_event(
            connection,
            principal.tenant_id,
            case_id,
            principal.subject_id,
            "CASE_UPDATED",
            from_status=str(existing["status"] or "OPEN").upper(),
            to_status=(normalized_status if request.status is not None else str(existing["status"] or "OPEN").upper()),
            changed_fields=changed_fields,
        )

        connection.commit()

        return {
            "success": True,
            "message": "Case updated successfully."
        }

    finally:

        connection.close()


# ==========================================
# ADD INVESTIGATION TO CASE
# ==========================================

@router.post("/{case_id}/investigations/{investigation_id}")
def attach_investigation(
    case_id: str,
    investigation_id: str,
    request: Request,
):
    principal = _require_analyst_identity(request)

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT case_id, status
            FROM cases
            WHERE case_id = ? AND tenant_id = ?
        """, (case_id, principal.tenant_id)).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        _enforce_case_claim_owner(connection, case_id, request)

        investigation = connection.execute("""
            SELECT
                investigation_id,
                threat_score
            FROM investigations
            WHERE investigation_id = ?
        """, (investigation_id,)).fetchone()

        if investigation is None:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found."
            )

        connection.execute("""
            INSERT OR IGNORE INTO case_investigations (
                case_id,
                investigation_id
            )
            VALUES (?, ?)
        """, (
            case_id,
            investigation_id
        ))

        connection.execute("""
            UPDATE cases
            SET
                threat_score = MAX(
                    threat_score,
                    ?
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE case_id = ? AND tenant_id = ?
        """, (
            int(investigation["threat_score"] or 0),
            case_id,
            principal.tenant_id,
        ))

        append_case_audit_event(
            connection,
            principal.tenant_id,
            case_id,
            principal.subject_id,
            "INVESTIGATION_ATTACHED",
            from_status=str(case["status"] or "OPEN"),
            to_status=str(case["status"] or "OPEN"),
            changed_fields=["investigation_link"],
        )

        connection.commit()

        return {
            "success": True,
            "message": "Investigation attached to case."
        }

    finally:

        connection.close()


# ==========================================
# ADD NOTE
# ==========================================

@router.post("/{case_id}/notes")
def add_case_note(
    case_id: str,
    request: AddNoteRequest,
    http_request: Request,
):

    principal = _require_analyst_identity(http_request)
    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT case_id, status
            FROM cases
            WHERE case_id = ? AND tenant_id = ?
        """, (case_id, principal.tenant_id)).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        _enforce_case_claim_owner(connection, case_id, http_request)

        cursor = connection.execute("""
            INSERT INTO case_notes (
                case_id,
                note,
                author
            )
            VALUES (?, ?, ?)
        """, (
            case_id,
            request.note,
            principal.subject_id
        ))

        append_case_audit_event(
            connection,
            principal.tenant_id,
            case_id,
            principal.subject_id,
            "ANALYST_NOTE_ADDED",
            from_status=str(case["status"] or "OPEN"),
            to_status=str(case["status"] or "OPEN"),
            changed_fields=["analyst_note"],
        )

        connection.commit()

        return {
            "success": True,
            "note_id": cursor.lastrowid
        }

    finally:

        connection.close()
