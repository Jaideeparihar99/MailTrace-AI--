from types import SimpleNamespace
from starlette.requests import Request
import main


def _request(tenant_id="tenant-a"):
    scope = {
        "type": "http", "method": "GET", "path": "/api/evidence/EVIDENCE-A",
        "headers": [], "query_string": b"", "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345), "scheme": "http", "http_version": "1.1",
        "asgi": {"version": "3.0"}, "state": {},
    }
    request = Request(scope)
    request.state.principal = SimpleNamespace(tenant_id=tenant_id, subject_id="test-analyst")
    return request


def test_evidence_lookup_error_is_sanitized(monkeypatch):
    monkeypatch.setattr(main.evidence_custody, "get", lambda _id: (_ for _ in ()).throw(RuntimeError("sqlite path C:/private/mailtrace.db")))
    try:
        main.get_evidence_record("EVIDENCE-A", _request())
    except main.HTTPException as exc:
        assert exc.status_code == 404
        assert "sqlite path" not in str(exc.detail)
        assert str(exc.detail) == "Evidence not found."
    else:
        raise AssertionError("expected sanitized evidence lookup error")


def test_evidence_integrity_error_is_sanitized(monkeypatch):
    monkeypatch.setattr(main.evidence_custody, "get", lambda _id: (_ for _ in ()).throw(RuntimeError("sqlite path C:/private/mailtrace.db")))
    try:
        main.verify_evidence_integrity("EVIDENCE-A", _request())
    except main.HTTPException as exc:
        assert exc.status_code == 404
        assert "sqlite path" not in str(exc.detail)
        assert str(exc.detail) == "Evidence not found."
    else:
        raise AssertionError("expected sanitized evidence integrity error")
