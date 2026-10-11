from __future__ import annotations

import database.database as db
import pytest
from scripts.configure_churu_local_intake import configure_queue


def setup_temp_db(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "mailtrace-test.db")
    monkeypatch.setattr(db, "is_production", lambda: False)


def test_churu_queue_dry_run_does_not_write_database(monkeypatch, tmp_path):
    setup_temp_db(monkeypatch, tmp_path)
    result = configure_queue(apply=False)
    assert result["applied"] is False
    assert result["preview"]["queue_id"] == "CHURU-SOC"
    assert result["preview"]["region_key"] == "CHURU"
    assert result["preview"]["external_dispatch"] == "NOT_CONFIGURED"
    assert not db.DATABASE_PATH.exists()


def test_churu_queue_bootstrap_is_idempotent_and_creates_no_fake_analysts(monkeypatch, tmp_path):
    setup_temp_db(monkeypatch, tmp_path)
    first = configure_queue(apply=True)
    second = configure_queue(apply=True)
    assert first["applied"] and second["applied"]
    assert first["queue"]["queue_id"] == "CHURU-SOC"
    assert second["queue"]["region_key"] == "CHURU"
    connection = db.get_connection()
    try:
        queues = connection.execute(
            "SELECT queue_id, region_key, name, active FROM soc_queues WHERE tenant_id='local' AND queue_id='CHURU-SOC'"
        ).fetchall()
        analysts = connection.execute(
            "SELECT COUNT(*) FROM soc_analysts WHERE tenant_id='local' AND region_key='CHURU'"
        ).fetchone()[0]
        events = connection.execute(
            "SELECT COUNT(*) FROM soc_routing_config_events WHERE tenant_id='local' AND action='QUEUE_CONFIGURED'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert len(queues) == 1
    assert queues[0]["active"] == 1
    assert analysts == 0
    assert events == 2  # Each explicit apply is audited; the queue row is not duplicated.


def test_churu_bootstrap_refuses_other_tenants(monkeypatch, tmp_path):
    setup_temp_db(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="local-development only"):
        configure_queue(apply=True, tenant_id="bank-production")
    assert not db.DATABASE_PATH.exists()


def test_churu_bootstrap_refuses_production_mode(monkeypatch, tmp_path):
    setup_temp_db(monkeypatch, tmp_path)
    monkeypatch.setattr(db, "is_production", lambda: True)
    with pytest.raises(RuntimeError, match="production mode"):
        configure_queue(apply=True)
    assert not db.DATABASE_PATH.exists()
