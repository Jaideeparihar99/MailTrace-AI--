import json

import pytest
from fastapi.testclient import TestClient

import database.database as db
import main
from services.access_control import ApiPrincipal


@pytest.fixture
def alert_api(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "alert-tenant-isolation.db")
    db.initialize_database()
    db.initialize_email_webhook_events()
    db.initialize_email_alerts()
    db.initialize_case_audit()

    db.save_investigation(
        "INV-TENANT-A", "tenant-a.eml", "A sensitive subject", "sender-a@example.invalid",
        "recipient-a@example.invalid", 96, "CRITICAL", "HIGH", json.dumps({"test": True}),
        tenant_id="tenant-a",
    )
    db.save_investigation(
        "INV-TENANT-B", "tenant-b.eml", "B confidential subject", "sender-b@example.invalid",
        "recipient-b@example.invalid", 98, "CRITICAL", "HIGH", json.dumps({"test": True}),
        tenant_id="tenant-b",
    )
    alert_a = db.create_email_alert(
        "event-tenant-a", "INV-TENANT-A", "CRITICAL", 96, "HIGH", "QUARANTINE", tenant_id="tenant-a",
    )
    alert_b = db.create_email_alert(
        "event-tenant-b", "INV-TENANT-B", "CRITICAL", 98, "HIGH", "QUARANTINE", tenant_id="tenant-b",
    )

    principals = {
        "token-a": ApiPrincipal(tenant_id="tenant-a", roles=frozenset({"analyst", "read", "write"}), subject_id="analyst-a"),
        "token-b": ApiPrincipal(tenant_id="tenant-b", roles=frozenset({"analyst", "read", "write"}), subject_id="analyst-b"),
        "token-employee": ApiPrincipal(tenant_id="tenant-a", roles=frozenset({"employee", "read", "write"}), subject_id="employee-a"),
    }
    monkeypatch.setattr(main, "configured_api_keys", lambda: {})
    monkeypatch.setattr(main, "authenticate_api_key", lambda token, _keys: principals.get(token))
    with TestClient(main.app) as client:
        yield client, alert_a, alert_b


def test_alert_listing_is_tenant_scoped_and_contains_no_other_tenant_email(alert_api):
    client, alert_a, alert_b = alert_api
    response = client.get("/api/alerts", headers={"Authorization": "Bearer token-a"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["count"] == 1
    assert payload["alerts"][0]["alert_id"] == alert_a["alert_id"]
    serialized = json.dumps(payload)
    assert "recipient-a@example.invalid" in serialized
    assert "recipient-b@example.invalid" not in serialized
    assert alert_b["alert_id"] not in serialized


def test_tenant_cannot_acknowledge_or_resolve_another_tenants_alert(alert_api):
    client, _alert_a, alert_b = alert_api
    headers = {"Authorization": "Bearer token-a"}
    alert_id = alert_b["alert_id"]
    ack = client.post(f"/api/alerts/{alert_id}/acknowledge", headers=headers)
    resolve = client.post(f"/api/alerts/{alert_id}/resolve", headers=headers)
    assert ack.status_code == 404
    assert resolve.status_code == 404
    connection = db.get_connection()
    try:
        row = connection.execute("SELECT status FROM email_alerts WHERE alert_id=?", (alert_id,)).fetchone()
    finally:
        connection.close()
    assert row["status"] == "NEW"


def test_tenant_cannot_read_another_tenants_history_or_gateway_integrity(alert_api):
    client, _alert_a, alert_b = alert_api
    headers = {"Authorization": "Bearer token-a"}
    alert_id = alert_b["alert_id"]
    history = client.get(f"/api/alerts/{alert_id}/history", headers=headers)
    integrity = client.get(f"/api/alerts/{alert_id}/gateway-action-integrity", headers=headers)
    assert history.status_code == 404
    assert integrity.status_code == 404


def test_employee_credentials_cannot_access_soc_alert_routes(alert_api):
    client, _alert_a, _alert_b = alert_api
    headers = {"Authorization": "Bearer token-employee"}
    listing = client.get("/api/alerts", headers=headers)
    acknowledgement = client.post(
        f"/api/alerts/{_alert_a['alert_id']}/acknowledge", headers=headers,
    )
    assert listing.status_code == 403
    assert acknowledgement.status_code == 403