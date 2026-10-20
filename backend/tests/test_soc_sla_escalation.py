import pathlib

import database.database as db


def test_sla_escalation_creates_tenant_scoped_alert_and_is_rate_limited(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "sla-escalation.db")
    db.initialize_database()
    db.initialize_case_claims()
    db.initialize_case_audit()
    db.initialize_soc_routing()

    connection = db.get_connection()
    try:
        connection.execute(
            "INSERT INTO cases(case_id, tenant_id, title, status, severity) VALUES(?,?,?,?,?)",
            ("CASE-SLA-A", "tenant-a", "Overdue critical case", "OPEN", "CRITICAL"),
        )
        connection.execute(
            "INSERT INTO cases(case_id, tenant_id, title, status, severity) VALUES(?,?,?,?,?)",
            ("CASE-SLA-CLOSED", "tenant-a", "Closed case", "CLOSED", "CRITICAL"),
        )
        connection.execute(
            "INSERT INTO cases(case_id, tenant_id, title, status, severity) VALUES(?,?,?,?,?)",
            ("CASE-SLA-B", "tenant-b", "Other tenant case", "OPEN", "CRITICAL"),
        )
        connection.commit()
    finally:
        connection.close()

    db.configure_soc_queue("tenant-a", "CENTRAL", "Central SOC", "CENTRAL", is_central=True)
    db.configure_soc_queue("tenant-b", "CENTRAL", "Central SOC", "CENTRAL", is_central=True)
    db.route_case_to_soc("CASE-SLA-A", "tenant-a", "reporter-a")
    db.route_case_to_soc("CASE-SLA-CLOSED", "tenant-a", "reporter-a")
    db.route_case_to_soc("CASE-SLA-B", "tenant-b", "reporter-b")

    connection = db.get_connection()
    try:
        connection.execute(
            "UPDATE case_routing SET sla_deadline='2000-01-01 00:00:00', priority='P1' WHERE tenant_id=? AND case_id IN (?,?)",
            ("tenant-a", "CASE-SLA-A", "CASE-SLA-CLOSED"),
        )
        connection.execute(
            "UPDATE case_routing SET sla_deadline='2000-01-01 00:00:00', priority='P1' WHERE tenant_id=? AND case_id=?",
            ("tenant-b", "CASE-SLA-B"),
        )
        connection.commit()
    finally:
        connection.close()

    assert db.process_sla_escalations("tenant-a") == 1
    assert db.process_sla_escalations("tenant-a") == 0

    connection = db.get_connection()
    try:
        alerts = connection.execute(
            "SELECT tenant_id, case_id, status, escalation_count FROM soc_sla_alerts ORDER BY case_id"
        ).fetchall()
        events = connection.execute(
            "SELECT tenant_id, case_id, action FROM case_routing_events WHERE action='SLA_ESCALATED'"
        ).fetchall()
    finally:
        connection.close()

    assert len(alerts) == 1
    assert dict(alerts[0]) == {
        "tenant_id": "tenant-a", "case_id": "CASE-SLA-A", "status": "OPEN", "escalation_count": 1
    }
    assert len(events) == 1
    assert dict(events[0])["tenant_id"] == "tenant-a"
    assert dict(events[0])["case_id"] == "CASE-SLA-A"


def test_new_overdue_escalation_reopens_resolved_sla_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "sla-reopen.db")
    db.initialize_database()
    db.initialize_case_claims()
    db.initialize_case_audit()
    db.initialize_soc_routing()
    connection = db.get_connection()
    try:
        connection.execute(
            "INSERT INTO cases(case_id, tenant_id, title, status, severity) VALUES(?,?,?,?,?)",
            ("CASE-SLA-REOPEN", "tenant-a", "Still overdue", "OPEN", "CRITICAL"),
        )
        connection.commit()
    finally:
        connection.close()
    db.configure_soc_queue("tenant-a", "CENTRAL", "Central SOC", "CENTRAL", is_central=True)
    db.route_case_to_soc("CASE-SLA-REOPEN", "tenant-a", "reporter-a")
    connection = db.get_connection()
    try:
        connection.execute(
            "UPDATE case_routing SET sla_deadline='2000-01-01 00:00:00', priority='P1' WHERE tenant_id=? AND case_id=?",
            ("tenant-a", "CASE-SLA-REOPEN"),
        )
        connection.commit()
    finally:
        connection.close()

    assert db.process_sla_escalations("tenant-a") == 1
    connection = db.get_connection()
    try:
        connection.execute(
            "UPDATE soc_sla_alerts SET status='RESOLVED' WHERE tenant_id=? AND case_id=?",
            ("tenant-a", "CASE-SLA-REOPEN"),
        )
        connection.execute(
            "UPDATE case_routing SET last_escalated_at='2000-01-01 00:00:00' WHERE tenant_id=? AND case_id=?",
            ("tenant-a", "CASE-SLA-REOPEN"),
        )
        connection.commit()
    finally:
        connection.close()

    assert db.process_sla_escalations("tenant-a") == 1
    connection = db.get_connection()
    try:
        alert = connection.execute(
            "SELECT status, escalation_count FROM soc_sla_alerts WHERE tenant_id=? AND case_id=?",
            ("tenant-a", "CASE-SLA-REOPEN"),
        ).fetchone()
    finally:
        connection.close()
    assert dict(alert) == {"status": "OPEN", "escalation_count": 2}
