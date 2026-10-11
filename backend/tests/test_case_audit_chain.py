from types import SimpleNamespace

import database.database as db
import pytest
from routes import cases


def test_case_status_and_analyst_note_are_audited_and_chain_verifies(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "case-audit.db")
    db.initialize_database()
    db.initialize_case_claims()
    db.initialize_case_audit()
    db.initialize_soc_routing()
    connection = db.get_connection()
    connection.execute(
        "INSERT INTO cases(case_id, tenant_id, title, status, severity) VALUES (?, ?, ?, ?, ?)",
        ("CASE-AUDIT", "tenant-a", "Audit test", "OPEN", "HIGH"),
    )
    connection.commit()
    connection.close()
    assignment, claimed = db.claim_case_for_analyst(
        "CASE-AUDIT", "tenant-a", "analyst-a", reason="triage"
    )
    assert claimed and assignment["assigned_analyst"] == "analyst-a"

    request = SimpleNamespace(
        state=SimpleNamespace(
            principal=SimpleNamespace(
                tenant_id="tenant-a",
                subject_id="analyst-a",
                roles=frozenset({"analyst"}),
                auth_method="api_key",
            )
        )
    )
    updated = cases.update_case(
        "CASE-AUDIT", cases.UpdateCaseRequest(status="CLOSED"), request
    )
    assert updated["success"] is True
    noted = cases.add_case_note(
        "CASE-AUDIT", cases.AddNoteRequest(note="Reviewed evidence"), request
    )
    assert noted["success"] is True
    history = cases.case_audit_history("CASE-AUDIT", request)
    assert history["integrity"]["valid"] is True
    assert [event["action"] for event in history["events"]] == [
        "CASE_UPDATED", "ANALYST_NOTE_ADDED"
    ]
    transition = history["events"][0]
    assert transition["actor_subject"] == "analyst-a"
    assert transition["from_status"] == "OPEN"
    assert transition["to_status"] == "CLOSED"
    assert transition["changed_fields"] == ["status"]


def test_case_audit_chain_detects_tampering_and_rejects_normal_edits(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "case-audit-tamper.db")
    db.initialize_database()
    db.initialize_case_audit()
    connection = db.get_connection()
    connection.execute("BEGIN IMMEDIATE")
    db.append_case_audit_event(
        connection,
        "tenant-a",
        "CASE-TAMPER",
        "analyst-a",
        "CASE_UPDATED",
        from_status="OPEN",
        to_status="CLOSED",
        changed_fields=["status"],
    )
    connection.commit()
    with pytest.raises(Exception):
        connection.execute(
            "UPDATE case_audit_events SET to_status='OPEN' WHERE case_id='CASE-TAMPER'"
        )
    connection.execute("DROP TRIGGER trg_case_audit_events_no_update")
    connection.execute(
        "UPDATE case_audit_events SET event_hash=? WHERE case_id='CASE-TAMPER'",
        ("a" * 64,),
    )
    connection.commit()
    connection.close()
    integrity = db.verify_case_audit_chain("tenant-a")
    assert integrity["valid"] is False
    assert integrity["first_invalid_event_id"] == 1


def test_employee_report_case_creation_and_followup_are_audited(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "employee-report-audit.db")
    db.initialize_database()
    db.initialize_employee_email_reports()
    db.initialize_case_audit()
    first, created = db.submit_employee_email_report(
        "tenant-a", "employee-1", "employee@example.invalid", "INV-REPORT",
        "made_payment", "Payment request was unexpected.",
    )
    assert created is True
    second, created_again = db.submit_employee_email_report(
        "tenant-a", "employee-1", "employee@example.invalid", "INV-REPORT",
        "made_payment", "I also verified the bank account details.",
    )
    assert created_again is False
    assert first["case_id"] == second["case_id"]
    events = db.get_case_audit_events("tenant-a", first["case_id"])
    assert [event["action"] for event in events] == [
        "EMPLOYEE_REPORT_CASE_CREATED", "EMPLOYEE_REPORT_UPDATED"
    ]
    assert all(event["actor_subject"] == "employee-1" for event in events)
    assert db.verify_case_audit_chain("tenant-a")["valid"] is True
