from services.threat_intelligence import sync_service


def test_failed_provider_partial_indicators_are_never_saved(monkeypatch):
    fake_result = {
        "success": True,
        "count": 2,
        "indicators": [
            {"source": "threatfox", "ioc": "evil.example", "ioc_type": "domain"},
            {"source": "urlhaus", "ioc": "https://bad.example/a", "ioc_type": "url"},
        ],
        "providers": {
            "threatfox": {"success": False, "configured": True, "count": 1, "status": "error"},
            "urlhaus": {"success": True, "configured": True, "count": 1, "status": "ok"},
        },
    }
    saved_batches = []
    monkeypatch.setattr(sync_service.ThreatIntelligenceEngine, "sync", lambda days: fake_result)
    monkeypatch.setattr(sync_service, "save_threat_intelligence", lambda batch: saved_batches.append(batch) or len(batch))
    monkeypatch.setattr(sync_service, "record_threat_intelligence_sync", lambda *args, **kwargs: 123)
    monkeypatch.setattr(sync_service, "get_threat_intelligence_source_status", lambda: {"coverage": "partial"})

    result = sync_service.sync_threat_intelligence_feeds(days=1, synced_by="test")

    assert saved_batches == [[], [{"source": "urlhaus", "ioc": "https://bad.example/a", "ioc_type": "url"}]]
    assert result["saved"] == 1
    assert result["sync_id"] == 123
    assert result["providers"]["threatfox"]["success"] is False


def test_successful_provider_with_malformed_indicator_is_not_saved(monkeypatch):
    fake_result = {
        "success": True,
        "count": 1,
        "indicators": [{"source": "urlhaus", "ioc": "", "ioc_type": "url"}],
        "providers": {"urlhaus": {"success": True, "configured": True, "count": 1, "status": "ok"}},
    }
    saved_batches = []
    monkeypatch.setattr(sync_service.ThreatIntelligenceEngine, "sync", lambda days: fake_result)
    monkeypatch.setattr(sync_service, "save_threat_intelligence", lambda batch: saved_batches.append(batch) or len(batch))
    monkeypatch.setattr(sync_service, "record_threat_intelligence_sync", lambda *args, **kwargs: 124)
    monkeypatch.setattr(sync_service, "get_threat_intelligence_source_status", lambda: {})

    result = sync_service.sync_threat_intelligence_feeds(days=1)

    assert saved_batches == [[]]
    assert result["saved"] == 0


def test_engine_preserves_safe_provider_error_classification(monkeypatch):
    from services.threat_intelligence import engine

    monkeypatch.setattr(engine, "fetch_threatfox", lambda days: {
        "success": False, "configured": True, "status": "error",
        "count": 0, "data": [], "error_type": "TimeoutError",
        "error": "sensitive raw provider details must not be returned",
    })
    monkeypatch.setattr(engine, "fetch_urlhaus_recent", lambda: {
        "success": True, "configured": True, "status": "ok",
        "count": 0, "data": [],
    })

    result = engine.ThreatIntelligenceEngine.sync(days=1)

    assert result["success"] is True
    assert result["providers"]["threatfox"]["error_type"] == "TimeoutError"
    assert "error" not in result["providers"]["threatfox"]
    assert "sensitive raw provider details" not in str(result["providers"])
