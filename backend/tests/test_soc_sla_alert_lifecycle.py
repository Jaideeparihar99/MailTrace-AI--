import pytest
from fastapi.testclient import TestClient

import database.database as db
import main
from services.access_control import ApiPrincipal


@pytest.fixture
def sla_api(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "soc-sla-api.db")
    db.initialize_database()
    db.initialize_case_claims()
    db.initialize_case_audit()
    db.initialize_soc_routing()
    connection = db.get_connection()
    try:
        for case_id, tenant_id in (("CASE-SLA-A", "tenant-a"), ("CASE-SLA-B", "tenant-b")):
            connection.execute(
                "INSERT INTO cases(case_id, tenant_id, title, status, severity) VALUES(?,?,?,?,?)",
                (case_id, tenant_id, "SLA test case", "OPEN", "CRITICAL"),
            )
            connection.execute(
                "INSERT INTO soc_sla_alerts(tenant_id, case_id, priority, sla_deadline, routing_status, status) VALUES(?,?,?,?,?,?)",
                (tenant_id, case_id, "P1", "2000-01-01 00:00:00", "ASSIGNED", "OPEN"),
            )
        connection.commit()
        alert_ids = {
            row["tenant_id"]: row["id"]
            for row in connection.execute("SELECT id, tenant_id FROM soc_sla_alerts").fetchall()
        }
    finally:
        connection.close()

    principals = {
        "token-a": ApiPrincipal(tenant_id="tenant-a", roles=frozenset({"analyst", "read", "write"}), subject_id="analyst-a"),
        "token-b": ApiPrincipal(tenant_id="tenant-b", roles=frozenset({"analyst", "read", "write"}), subject_id="analyst-b"),
    }
    monkeypatch.setattr(main, "configured_api_keys", lambda: {})
    monkeypatch.setattr(main, "authenticate_api_key", lambda token, _keys: principals.get(token))
    with TestClient(main.app) as client:
        yield client, alert_ids


def test_sla_alert_lifecycle_is_authenticated_audited_and_ordered(sla_api):
    client, alert_ids = sla_api
    alert_id = alert_ids["tenant-a"]
    headers = {"Authorization": "Bearer token-a"}

    assert client.get("/api/soc/routing/alerts").status_code == 401
    ack = client.post(f"/api/soc/routing/alerts/{alert_id}/acknowledge", headers=headers)
    assert ack.status_code == 200, ack.text
    assert ack.json()["status"] == "ACKNOWLEDGED"
    assert ack.json()["actor_subject"] == "analyst-a"

    duplicate_ack = client.post(f"/api/soc/routing/alerts/{alert_id}/acknowledge", headers=headers)
    assert duplicate_ack.status_code == 409
    resolve = client.post(f"/api/soc/routing/alerts/{alert_id}/resolve", headers=headers)
    assert resolve.status_code == 200, resolve.text
    assert resolve.json()["status"] == "RESOLVED"
    duplicate_resolve = client.post(f"/api/soc/routing/alerts/{alert_id}/resolve", headers=headers)
    assert duplicate_resolve.status_code == 409

    connection = db.get_connection()
    try:
        row = connection.execute("SELECT status FROM soc_sla_alerts WHERE id=?", (alert_id,)).fetchone()
        events = connection.execute(
            "SELECT actor_subject, action, from_status, to_status FROM soc_sla_alert_events WHERE alert_id=? ORDER BY id",
            (alert_id,),
        ).fetchall()
    finally:
        connection.close()
    assert row["status"] == "RESOLVED"
    assert [dict(event) for event in events] == [
        {"actor_subject": "analyst-a", "action": "ACKNOWLEDGED", "from_status": "OPEN", "to_status": "ACKNOWLEDGED"},
        {"actor_subject": "analyst-a", "action": "RESOLVED", "from_status": "ACKNOWLEDGED", "to_status": "RESOLVED"},
    ]


def test_sla_alert_transitions_are_tenant_scoped(sla_api):
    client, alert_ids = sla_api
    other_tenant_alert = alert_ids["tenant-b"]
    headers = {"Authorization": "Bearer token-a"}
    assert client.post(f"/api/soc/routing/alerts/{other_tenant_alert}/acknowledge", headers=headers).status_code == 404
    assert client.get("/api/soc/routing/alerts?status=ALL", headers=headers).json()["count"] == 1
    connection = db.get_connection()
    try:
        row = connection.execute("SELECT status FROM soc_sla_alerts WHERE id=?", (other_tenant_alert,)).fetchone()
        events = connection.execute("SELECT COUNT(*) AS n FROM soc_sla_alert_events WHERE alert_id=?", (other_tenant_alert,)).fetchone()
    finally:
        connection.close()
    assert row["status"] == "OPEN"
    assert events["n"] == 0
