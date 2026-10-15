import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import database.database as db
from routes.cases import router as cases_router
from routes.soc_routing import router as soc_routing_router


@pytest.fixture()
def soc_client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "soc-cases.db")
    db.initialize_database()
    db.initialize_email_alerts()
    db.initialize_employee_email_reports()
    db.initialize_case_claims()
    db.initialize_case_audit()
    db.initialize_soc_routing()
    connection = db.get_connection()
    connection.executemany(
        "INSERT INTO cases(case_id, tenant_id, title, severity, status) VALUES (?, ?, ?, ?, 'OPEN')",
        [
            ("CASE-A", "tenant-a", "Tenant A case", "HIGH"),
            ("CASE-B", "tenant-b", "Tenant B case", "CRITICAL"),
            ("CASE-RACE", "tenant-a", "Race case", "HIGH"),
        ],
    )
    connection.commit()
    connection.close()

    app = FastAPI()

    @app.middleware("http")
    async def test_identity(request, call_next):
        request.state.principal = SimpleNamespace(
            tenant_id=request.headers.get("x-tenant", "tenant-a"),
            subject_id=request.headers.get("x-subject", "analyst-a"),
            roles=frozenset(request.headers.get("x-roles", "analyst").split(",")),
        )
        return await call_next(request)

    app.include_router(cases_router)
    app.include_router(soc_routing_router)
    return TestClient(app)


def headers(subject="analyst-a", tenant="tenant-a", roles="analyst"):
    return {"x-subject": subject, "x-tenant": tenant, "x-roles": roles}


def test_same_analyst_claim_renews_and_audits_reason(soc_client):
    first = soc_client.post("/api/cases/CASE-A/claim", headers=headers(), json={"reason": "triage"})
    assert first.status_code == 200, first.text
    second = soc_client.post("/api/cases/CASE-A/claim", headers=headers(), json={"reason": "still investigating"})
    assert second.status_code == 200, second.text
    history = soc_client.get("/api/cases/CASE-A/history", headers=headers())
    assert history.status_code == 200, history.text
    events = history.json()["events"]
    assert [event["action"] for event in events] == ["CLAIMED", "RENEWED"]
    assert '"reason":"triage"' in events[0]["details_json"]



def test_claim_and_release_sync_soc_routing_owner(soc_client):
    db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    claimed = soc_client.post("/api/cases/CASE-A/claim", headers=headers(), json={"reason": "triage case"})
    assert claimed.status_code == 200, claimed.text
    routing = db.get_case_routing("CASE-A", "tenant-a")
    assert routing["assigned_analyst"] == "analyst-a"
    assert routing["status"] == "ASSIGNED"
    queue = soc_client.get("/api/soc/routing/queue", headers=headers()).json()
    item = next(case for case in queue["cases"] if case["case_id"] == "CASE-A")
    assert item["assigned_analyst"] == "analyst-a"
    assert item["claim_owner"] == "analyst-a"

    released = soc_client.post("/api/cases/CASE-A/release", headers=headers(), json={"reason": "handoff to queue"})
    assert released.status_code == 200, released.text
    routing = db.get_case_routing("CASE-A", "tenant-a")
    assert routing["assigned_analyst"] is None
    assert routing["status"] == "QUEUED"
    queue = soc_client.get("/api/soc/routing/queue", headers=headers()).json()
    item = next(case for case in queue["cases"] if case["case_id"] == "CASE-A")
    assert item["assigned_analyst"] is None
    assert item["claim_owner"] is None


def test_second_analyst_conflict_returns_current_owner(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    response = soc_client.post("/api/cases/CASE-A/claim", headers=headers("analyst-b"))
    assert response.status_code == 409
    assert response.json()["detail"]["assignment"]["assigned_analyst"] == "analyst-a"


def test_expired_claim_can_be_reclaimed(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    connection = db.get_connection()
    connection.execute("UPDATE case_claims SET lease_expires_at=datetime('now', '-1 minute') WHERE case_id='CASE-A'")
    connection.commit()
    connection.close()
    response = soc_client.post("/api/cases/CASE-A/claim", headers=headers("analyst-b"))
    assert response.status_code == 200, response.text
    assert response.json()["assignment"]["assigned_analyst"] == "analyst-b"
    history = soc_client.get("/api/cases/CASE-A/history", headers=headers("analyst-b"))
    assert history.json()["events"][-1]["action"] == "RECLAIMED_EXPIRED"


def test_release_only_by_current_owner_and_reason_is_audited(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    denied = soc_client.post("/api/cases/CASE-A/release", headers=headers("analyst-b"))
    assert denied.status_code == 409
    released = soc_client.post("/api/cases/CASE-A/release", headers=headers(), json={"reason": "handoff"})
    assert released.status_code == 200, released.text
    events = soc_client.get("/api/cases/CASE-A/history", headers=headers()).json()["events"]
    assert events[-1]["action"] == "RELEASED"
    assert '"reason":"handoff"' in events[-1]["details_json"]


def test_renew_requires_current_unexpired_owner(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    assert soc_client.post("/api/cases/CASE-A/renew", headers=headers("analyst-b")).status_code == 409
    connection = db.get_connection()
    connection.execute("UPDATE case_claims SET lease_expires_at=datetime('now', '-1 minute') WHERE case_id='CASE-A'")
    connection.commit()
    connection.close()
    assert soc_client.post("/api/cases/CASE-A/renew", headers=headers()).status_code == 409


def test_wrong_tenant_cannot_claim_read_or_mutate(soc_client):
    assert soc_client.get("/api/cases/CASE-A", headers=headers(tenant="tenant-b")).status_code == 404
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers(tenant="tenant-b")).status_code == 404
    assert soc_client.patch("/api/cases/CASE-A", headers=headers(tenant="tenant-b"), json={"status": "CLOSED"}).status_code == 404


def test_employee_role_denied_from_soc_case_data(soc_client):
    response = soc_client.get("/api/cases/CASE-A", headers=headers(roles="employee"))
    assert response.status_code == 403


def test_mutations_require_active_claim_owner_and_note_author_is_verified(soc_client):
    patch = soc_client.patch("/api/cases/CASE-A", headers=headers(), json={"status": "CLOSED"})
    assert patch.status_code == 423
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    denied = soc_client.patch("/api/cases/CASE-A", headers=headers("analyst-b"), json={"status": "CLOSED"})
    assert denied.status_code == 423
    note = soc_client.post("/api/cases/CASE-A/notes", headers=headers(), json={"note": "checked", "author": "spoofed"})
    assert note.status_code == 200, note.text
    updated = soc_client.patch("/api/cases/CASE-A", headers=headers(), json={"status": "CLOSED"})
    assert updated.status_code == 200, updated.text
    history = soc_client.get("/api/cases/CASE-A/audit", headers=headers())
    assert history.status_code == 200, history.text
    assert history.json()["integrity"]["valid"] is True
    assert [event["action"] for event in history.json()["events"]] == [
        "ANALYST_NOTE_ADDED", "CASE_UPDATED"
    ]
    assert history.json()["events"][1]["actor_subject"] == "analyst-a"
    assert history.json()["events"][1]["from_status"] == "OPEN"
    assert history.json()["events"][1]["to_status"] == "CLOSED"
    connection = db.get_connection()
    author = connection.execute("SELECT author FROM case_notes WHERE case_id='CASE-A'").fetchone()[0]
    connection.close()
    assert author == "analyst-a"


def test_concurrent_claim_race_has_exactly_one_owner(soc_client):
    def attempt(subject):
        return db.claim_case_for_analyst("CASE-RACE", "tenant-a", subject)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, [f"analyst-{i}" for i in range(8)]))
    winners = [assignment for assignment, ok in results if ok]
    assert len(winners) == 1
    connection = db.get_connection()
    active = connection.execute("SELECT COUNT(*) FROM case_claims WHERE case_id='CASE-RACE' AND status='ACTIVE' AND datetime(lease_expires_at)>datetime('now')").fetchone()[0]
    connection.close()
    assert active == 1


def test_claim_audit_is_append_only(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    connection = db.get_connection()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE case_claim_events SET action='TAMPERED' WHERE case_id='CASE-A'")
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM case_claim_events WHERE case_id='CASE-A'")
    connection.close()


def test_list_cases_is_tenant_scoped_and_returns_claim_status(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    response = soc_client.get("/api/cases", headers=headers())
    assert response.status_code == 200, response.text
    case_ids = {case["case_id"] for case in response.json()["cases"]}
    assert "CASE-A" in case_ids
    assert "CASE-B" not in case_ids
    case = next(case for case in response.json()["cases"] if case["case_id"] == "CASE-A")
    assert case["assigned_analyst"] == "analyst-a"



def test_idempotency_key_replays_claim_without_duplicate_audit(soc_client):
    key_headers = {**headers(), "Idempotency-Key": "claim-request-001"}
    first = soc_client.post("/api/cases/CASE-A/claim", headers=key_headers, json={"reason": "triage"})
    second = soc_client.post("/api/cases/CASE-A/claim", headers=key_headers, json={"reason": "triage"})
    assert first.status_code == second.status_code == 200
    assert first.json()["assignment"]["lease_expires_at"] == second.json()["assignment"]["lease_expires_at"]
    events = soc_client.get("/api/cases/CASE-A/history", headers=headers()).json()["events"]
    assert len(events) == 1


def test_existing_case_schema_migrates_safely_to_tenant_scope(tmp_path, monkeypatch):
    legacy_db = tmp_path / "legacy.db"
    monkeypatch.setattr(db, "DATABASE_PATH", legacy_db)
    monkeypatch.setenv("MAILTRACE_ENV", "development")
    connection = sqlite3.connect(legacy_db)
    connection.execute("CREATE TABLE cases (id INTEGER PRIMARY KEY, case_id TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT, severity TEXT DEFAULT 'LOW', status TEXT DEFAULT 'OPEN', threat_score INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    connection.execute("INSERT INTO cases(case_id,title) VALUES ('LEGACY-1','Legacy case')")
    connection.commit()
    connection.close()
    db.initialize_database()
    connection = db.get_connection()
    migrated = connection.execute("SELECT tenant_id FROM cases WHERE case_id='LEGACY-1'").fetchone()[0]
    connection.close()
    assert migrated == "local"


def test_production_legacy_cases_are_quarantined_until_mapped(tmp_path, monkeypatch):
    legacy_db = tmp_path / "legacy-prod.db"
    monkeypatch.setattr(db, "DATABASE_PATH", legacy_db)
    monkeypatch.setenv("MAILTRACE_ENV", "production")
    monkeypatch.setenv(
        "MAILTRACE_DATA_ENCRYPTION_KEY",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    connection = sqlite3.connect(legacy_db)
    connection.execute("CREATE TABLE cases (id INTEGER PRIMARY KEY, case_id TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT, severity TEXT DEFAULT 'LOW', status TEXT DEFAULT 'OPEN', threat_score INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    connection.execute("INSERT INTO cases(case_id,title) VALUES ('LEGACY-2','Legacy production case')")
    connection.commit()
    connection.close()
    db.initialize_database()
    connection = db.get_connection()
    migrated = connection.execute("SELECT tenant_id FROM cases WHERE case_id='LEGACY-2'").fetchone()[0]
    connection.close()
    assert migrated == "__legacy_unassigned__"



def test_production_case_access_rejects_static_api_key_identity(soc_client, monkeypatch):
    monkeypatch.setenv("MAILTRACE_ENV", "production")
    response = soc_client.get("/api/cases/CASE-A", headers=headers())
    assert response.status_code == 403
    assert "OIDC" in response.json()["detail"]



def test_routing_uses_verified_employee_region_skills_and_workload(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", team_key="SOC-NORTH", actor_subject="lead-a", reason="regional team setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", team_key="SOC-NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", team_key="SOC-NORTH", skills=["phishing", "url-analysis"], max_open_cases=2, actor_subject="lead-a", reason="analyst roster")
    db.configure_soc_analyst("tenant-a", "analyst-b", "NORTH", team_key="SOC-NORTH", skills=["malware-analysis"], max_open_cases=2, actor_subject="lead-a", reason="analyst roster")
    first = db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    assert first["region_key"] == "NORTH"
    assert first["queue_id"] == "NORTH-QUEUE"
    assert first["assigned_analyst"] == "analyst-a"
    assert first["priority"] == "P2"
    assert first["sla_deadline"]
    # The same verified employee region routes a second case to the less-loaded eligible analyst.
    second = db.route_case_to_soc("CASE-RACE", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    assert second["assigned_analyst"] == "analyst-a"  # analyst-b lacks the required skill


def test_unverified_employee_region_falls_back_and_unassigned_case_is_retained(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="regional queue setup")
    result = db.route_case_to_soc("CASE-A", "tenant-a", "unmapped-employee", actor_subject="system:test", required_skills=["phishing"])
    assert result["queue_id"] == "CENTRAL"
    assert result["assigned_analyst"] is None
    assert result["status"] == "QUEUED"
    assert "no_verified_employee_region" in result["routing_reason"]
    events = db.get_case_routing_events("CASE-A", "tenant-a")
    assert events[-1]["action"] == "NO_ELIGIBLE_ANALYST"


def test_sla_escalation_is_persisted_and_rate_limited(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="queue setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    connection = db.get_connection()
    connection.execute("UPDATE case_routing SET sla_deadline=datetime('now','-2 minutes') WHERE case_id='CASE-A' AND tenant_id='tenant-a'")
    connection.commit()
    connection.close()
    assert db.process_sla_escalations("tenant-a") == 1
    assert db.process_sla_escalations("tenant-a") == 0
    events = db.get_case_routing_events("CASE-A", "tenant-a")
    assert events[-1]["action"] == "SLA_ESCALATED"
    connection = db.get_connection()
    alert = connection.execute("SELECT * FROM soc_sla_alerts WHERE tenant_id='tenant-a' AND case_id='CASE-A'").fetchone()
    connection.close()
    assert alert is not None
    assert alert["status"] == "OPEN"
    assert alert["sla_deadline"]
    response = soc_client.get("/api/soc/routing/alerts", headers=headers("analyst-a"))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["count"] == 1
    assert payload["alerts"][0]["case_id"] == "CASE-A"
    assert payload["alerts"][0]["overdue"] == 1


def test_manual_override_requires_lead_and_reason_is_audited(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="queue setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    db.configure_soc_analyst("tenant-a", "analyst-b", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers("analyst-a")).status_code == 200
    denied = soc_client.post("/api/soc/routing/cases/CASE-A/assign", headers=headers("lead-a", roles="analyst"), json={"analyst_subject":"analyst-b","reason":"urgent reassignment"})
    assert denied.status_code == 403
    allowed = soc_client.post("/api/soc/routing/cases/CASE-A/assign", headers=headers("lead-a", roles="soc_lead"), json={"analyst_subject":"analyst-b","reason":"urgent reassignment"})
    assert allowed.status_code == 200, allowed.text
    claim = db.get_connection()
    owner = claim.execute("SELECT assigned_analyst FROM case_claims WHERE case_id='CASE-A' AND tenant_id='tenant-a'").fetchone()[0]
    claim.close()
    assert owner == "analyst-b"
    claim_events = soc_client.get("/api/cases/CASE-A/history", headers=headers("analyst-b")).json()["events"]
    assert claim_events[-1]["action"] == "MANUAL_REASSIGN"
    assert '"reason":"urgent reassignment"' in claim_events[-1]["details_json"]
    events = db.get_case_routing_events("CASE-A", "tenant-a")
    assert events[-1]["action"] == "MANUAL_OVERRIDE"
    assert events[-1]["reason"] == "urgent reassignment"


def test_routed_case_cannot_be_claimed_by_unassigned_other_analyst(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="queue setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    db.configure_soc_analyst("tenant-a", "analyst-b", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    denied = soc_client.post("/api/cases/CASE-A/claim", headers=headers("analyst-b"))
    assert denied.status_code == 409
    assert "assigned to analyst-a" in denied.json()["detail"]["message"]


def test_routing_queue_and_history_are_tenant_scoped(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="queue setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    own = soc_client.get("/api/soc/routing/queue", headers=headers())
    other = soc_client.get("/api/soc/routing/queue", headers=headers(tenant="tenant-b"))
    assert own.status_code == other.status_code == 200
    assert any(item["case_id"] == "CASE-A" for item in own.json()["cases"])
    assert all(item["case_id"] != "CASE-A" for item in other.json()["cases"])
    assert soc_client.get("/api/soc/routing/cases/CASE-A/history", headers=headers(tenant="tenant-b")).status_code == 404



def test_soc_action_rate_limit_is_atomic_and_scoped(soc_client):
    assert db.allow_soc_action("tenant-a", "analyst-a", "test-action", limit=2, window_seconds=60)
    assert db.allow_soc_action("tenant-a", "analyst-a", "test-action", limit=2, window_seconds=60)
    assert not db.allow_soc_action("tenant-a", "analyst-a", "test-action", limit=2, window_seconds=60)
    assert db.allow_soc_action("tenant-a", "analyst-b", "test-action", limit=2, window_seconds=60)
    assert db.allow_soc_action("tenant-b", "analyst-a", "test-action", limit=2, window_seconds=60)



def test_owner_can_renew_an_unexpired_claim(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    response = soc_client.post("/api/cases/CASE-A/renew", headers={**headers(), "Idempotency-Key":"renew-owner-1"}, json={"reason":"active investigation"})
    assert response.status_code == 200, response.text
    events = soc_client.get("/api/cases/CASE-A/history", headers=headers()).json()["events"]
    assert events[-1]["action"] == "RENEWED"
    assert '"reason":"active investigation"' in events[-1]["details_json"]


def test_investigation_attachment_requires_active_claim_owner(soc_client):
    unclaimed = soc_client.post("/api/cases/CASE-A/investigations/INV-TEST", headers=headers())
    assert unclaimed.status_code == 423
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers()).status_code == 200
    other_owner = soc_client.post("/api/cases/CASE-A/investigations/INV-TEST", headers=headers("analyst-b"))
    assert other_owner.status_code == 423



def test_legacy_soc_routing_schema_upgrades_without_dropping_rows(tmp_path, monkeypatch):
    legacy_db = tmp_path / "legacy-routing.db"
    monkeypatch.setattr(db, "DATABASE_PATH", legacy_db)
    monkeypatch.setenv("MAILTRACE_ENV", "development")
    db.initialize_database()
    db.initialize_email_alerts()
    db.initialize_employee_email_reports()
    db.initialize_case_claims()
    connection = db.get_connection()
    connection.execute("INSERT INTO cases(case_id,tenant_id,title,severity,status,threat_score) VALUES ('LEGACY-ROUTE','tenant-a','Existing routed case','HIGH','OPEN',80)")
    connection.executescript("""
        CREATE TABLE soc_queues (
            id INTEGER PRIMARY KEY AUTOINCREMENT, queue_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
            name TEXT NOT NULL, region_key TEXT NOT NULL, is_central INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(tenant_id, queue_id), UNIQUE(tenant_id, name)
        );
        CREATE TABLE employee_region_assignments (
            tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, region_key TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'admin_config', active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(tenant_id, subject_id)
        );
        CREATE TABLE soc_analysts (
            tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, region_key TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1, max_open_cases INTEGER NOT NULL DEFAULT 20,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(tenant_id, subject_id)
        );
        CREATE TABLE case_routing (
            case_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, region_key TEXT NOT NULL,
            queue_id TEXT NOT NULL, assigned_analyst TEXT,
            status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','ASSIGNED','FALLBACK','UNROUTED')),
            routing_reason TEXT NOT NULL DEFAULT '', assigned_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE case_routing_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
            actor_subject TEXT, action TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO soc_queues(queue_id,tenant_id,name,region_key) VALUES ('NORTH','tenant-a','North SOC','NORTH');
        INSERT INTO employee_region_assignments(tenant_id,subject_id,region_key) VALUES ('tenant-a','employee-sub','NORTH');
        INSERT INTO soc_analysts(tenant_id,subject_id,region_key) VALUES ('tenant-a','analyst-a','NORTH');
        INSERT INTO case_routing(case_id,tenant_id,region_key,queue_id,status) VALUES ('LEGACY-ROUTE','tenant-a','NORTH','NORTH','QUEUED');
    """)
    connection.commit()
    connection.close()

    db.initialize_soc_routing()
    migrated = db.get_case_routing("LEGACY-ROUTE", "tenant-a")
    assert migrated is not None
    assert migrated["last_activity_at"]
    assert migrated["priority"] == "P3"
    analyst = db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="schema migration verification")
    assert analyst["availability"] == "AVAILABLE"
    routed = db.route_case_to_soc("LEGACY-ROUTE", "tenant-a", "employee-sub", actor_subject="lead-a", required_skills=["phishing"])
    assert routed["assigned_analyst"] == "analyst-a"
    events = db.get_case_routing_events("LEGACY-ROUTE", "tenant-a")
    assert events[-1]["action"] == "ROUTED"



def test_routing_reconciliation_preserves_live_claim_owner(soc_client):
    assert soc_client.post("/api/cases/CASE-A/claim", headers=headers("analyst-b")).status_code == 200
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="queue setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    routed = db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:reconcile", required_skills=["phishing"])
    assert routed["assigned_analyst"] == "analyst-b"
    assert "preserved_active_claim_owner" in routed["routing_reason"]


def test_sla_deadline_is_never_extended_when_severity_escalates(soc_client):
    db.configure_soc_queue("tenant-a", "NORTH-QUEUE", "North SOC", "NORTH", actor_subject="lead-a", reason="queue setup")
    db.configure_employee_region("tenant-a", "employee-subject", "NORTH", actor_subject="lead-a", reason="verified HR mapping")
    db.configure_soc_analyst("tenant-a", "analyst-a", "NORTH", skills=["phishing"], actor_subject="lead-a", reason="analyst roster")
    initial = db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:test", required_skills=["phishing"])
    connection = db.get_connection()
    connection.execute("UPDATE case_routing SET sla_deadline=datetime('now','+5 minutes') WHERE case_id='CASE-A' AND tenant_id='tenant-a'")
    connection.execute("UPDATE cases SET threat_score=99 WHERE case_id='CASE-A' AND tenant_id='tenant-a'")
    connection.commit()
    before = connection.execute("SELECT sla_deadline FROM case_routing WHERE case_id='CASE-A' AND tenant_id='tenant-a'").fetchone()[0]
    connection.close()
    updated = db.route_case_to_soc("CASE-A", "tenant-a", "employee-subject", actor_subject="system:repeat", required_skills=["phishing"])
    assert updated["priority"] == "P1"
    assert updated["sla_deadline"] == before



def test_sla_alert_acknowledge_resolve_are_tenant_scoped_and_audited(soc_client):
    connection = db.get_connection()
    connection.executemany(
        """INSERT INTO soc_sla_alerts
           (tenant_id, case_id, alert_type, priority, sla_deadline, assigned_analyst, routing_status, escalation_count, status)
           VALUES (?, ?, 'SLA_OVERDUE', 'P1', datetime('now','-5 minutes'), ?, 'ASSIGNED', 2, 'OPEN')""",
        [("tenant-a", "CASE-A", "analyst-a"), ("tenant-b", "CASE-B", "analyst-b")],
    )
    connection.commit()
    alert_id = connection.execute(
        "SELECT id FROM soc_sla_alerts WHERE tenant_id='tenant-a' AND case_id='CASE-A'"
    ).fetchone()[0]
    other_tenant_id = connection.execute(
        "SELECT id FROM soc_sla_alerts WHERE tenant_id='tenant-b' AND case_id='CASE-B'"
    ).fetchone()[0]
    connection.close()

    listing = soc_client.get("/api/soc/routing/alerts?status=ALL", headers=headers())
    assert listing.status_code == 200, listing.text
    assert listing.json()["count"] == 1
    assert listing.json()["alerts"][0]["alert_id"] == alert_id
    assert soc_client.get("/api/soc/routing/alerts?status=NOT_A_STATUS", headers=headers()).status_code == 422
    assert soc_client.post("/api/soc/routing/alerts/999999/acknowledge", headers=headers()).status_code == 404
    # Resolve is not permitted directly from OPEN; acknowledge must happen first.
    assert soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/resolve", headers=headers()
    ).status_code == 409

    forbidden_role = soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/acknowledge",
        headers=headers(roles="read"),
    )
    assert forbidden_role.status_code == 403

    acknowledged = soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/acknowledge", headers=headers()
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["status"] == "ACKNOWLEDGED"
    assert acknowledged.json()["actor_subject"] == "analyst-a"
    repeated_ack = soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/acknowledge", headers=headers()
    )
    assert repeated_ack.status_code == 409

    connection = db.get_connection()
    stored = connection.execute(
        "SELECT status FROM soc_sla_alerts WHERE id=? AND tenant_id='tenant-a'", (alert_id,)
    ).fetchone()[0]
    audit = connection.execute(
        "SELECT actor_subject, action, from_status, to_status, created_at FROM soc_sla_alert_events WHERE alert_id=? AND tenant_id='tenant-a' ORDER BY id",
        (alert_id,),
    ).fetchall()
    connection.close()
    assert stored == "ACKNOWLEDGED"
    assert len(audit) == 1
    assert tuple(audit[0][:4]) == ("analyst-a", "ACKNOWLEDGED", "OPEN", "ACKNOWLEDGED")
    assert audit[0]["created_at"]

    # A different tenant cannot see or mutate the first tenant's alert ID.
    assert soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/resolve", headers=headers(tenant="tenant-b", subject="analyst-b")
    ).status_code == 404
    assert soc_client.post(
        f"/api/soc/routing/alerts/{other_tenant_id}/acknowledge", headers=headers()
    ).status_code == 404

    resolved = soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/resolve", headers=headers()
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "RESOLVED"
    repeated_resolve = soc_client.post(
        f"/api/soc/routing/alerts/{alert_id}/resolve", headers=headers()
    )
    assert repeated_resolve.status_code == 409

    connection = db.get_connection()
    stored = connection.execute(
        "SELECT status FROM soc_sla_alerts WHERE id=? AND tenant_id='tenant-a'", (alert_id,)
    ).fetchone()[0]
    audit = connection.execute(
        "SELECT actor_subject, action, from_status, to_status FROM soc_sla_alert_events WHERE alert_id=? AND tenant_id='tenant-a' ORDER BY id",
        (alert_id,),
    ).fetchall()
    connection.close()
    assert stored == "RESOLVED"
    assert [tuple(row) for row in audit] == [
        ("analyst-a", "ACKNOWLEDGED", "OPEN", "ACKNOWLEDGED"),
        ("analyst-a", "RESOLVED", "ACKNOWLEDGED", "RESOLVED"),
    ]


def test_sla_alert_routes_require_an_attached_verified_principal(soc_client):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes.soc_routing import router as sla_router

    app = FastAPI()
    app.include_router(sla_router)
    client = TestClient(app)
    assert client.get("/api/soc/routing/alerts").status_code == 401
    assert client.post("/api/soc/routing/alerts/1/acknowledge").status_code == 401
    assert client.post("/api/soc/routing/alerts/1/resolve").status_code == 401



def test_sla_alert_workflow_through_real_local_auth_middleware(tmp_path, monkeypatch):
    import main
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "authenticated-sla-e2e.db")
    db.initialize_database()
    db.initialize_email_alerts()
    db.initialize_case_claims()
    db.initialize_soc_routing()
    connection = db.get_connection()
    connection.execute(
        "INSERT INTO cases(case_id, tenant_id, title, severity, status) VALUES ('E2E-SLA-1','local','Synthetic SLA test','HIGH','OPEN')"
    )
    connection.execute(
        """INSERT INTO soc_sla_alerts
           (tenant_id, case_id, alert_type, priority, sla_deadline, assigned_analyst, routing_status, escalation_count, status)
           VALUES ('local','E2E-SLA-1','SLA_OVERDUE','P2',datetime('now','-5 minutes'),'local-dev-analyst','ASSIGNED',1,'OPEN')"""
    )
    connection.commit()
    alert_id = connection.execute(
        "SELECT id FROM soc_sla_alerts WHERE tenant_id='local' AND case_id='E2E-SLA-1'"
    ).fetchone()[0]
    connection.close()

    app = FastAPI()
    app.middleware("http")(main.authenticate_api_requests)
    app.include_router(soc_routing_router)
    client = TestClient(app, client=("127.0.0.1", 54321))

    first = client.get("/api/soc/routing/alerts?status=OPEN")
    assert first.status_code == 200, first.text
    assert first.json()["count"] == 1
    assert first.json()["alerts"][0]["alert_id"] == alert_id
    assert first.json()["alerts"][0]["status"] == "OPEN"

    ack = client.post(f"/api/soc/routing/alerts/{alert_id}/acknowledge")
    assert ack.status_code == 200, ack.text
    assert client.get("/api/soc/routing/alerts?status=ACKNOWLEDGED").json()["alerts"][0]["status"] == "ACKNOWLEDGED"

    resolved = client.post(f"/api/soc/routing/alerts/{alert_id}/resolve")
    assert resolved.status_code == 200, resolved.text
    after_reload = client.get("/api/soc/routing/alerts?status=RESOLVED")
    assert after_reload.status_code == 200
    assert after_reload.json()["count"] == 1
    assert after_reload.json()["alerts"][0]["status"] == "RESOLVED"

    connection = db.get_connection()
    events = connection.execute(
        "SELECT actor_subject, action, from_status, to_status FROM soc_sla_alert_events WHERE alert_id=? ORDER BY id",
        (alert_id,),
    ).fetchall()
    connection.close()
    assert [tuple(row) for row in events] == [
        ("local-dev-analyst", "ACKNOWLEDGED", "OPEN", "ACKNOWLEDGED"),
        ("local-dev-analyst", "RESOLVED", "ACKNOWLEDGED", "RESOLVED"),
    ]

    non_loopback = TestClient(app, client=("203.0.113.9", 54321))
    denied = non_loopback.get("/api/soc/routing/alerts")
    assert denied.status_code == 401
