from fastapi import HTTPException, Request
from starlette.requests import Request as StarletteRequest
import routes.investigations as inv_routes


def request_with_principal(principal=None):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/investigations",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "scheme": "http",
        "http_version": "1.1",
        "asgi": {"version": "3.0"},
        "state": {},
    }
    request = StarletteRequest(scope)
    if principal is not None:
        request.state.principal = principal
    return request


def test_investigation_list_fails_closed_without_principal():
    try:
        inv_routes.list_investigations(request_with_principal())
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("missing principal must not query investigations")


def test_single_investigation_fails_closed_without_principal():
    try:
        inv_routes.get_single_investigation("INV-OTHER", request_with_principal())
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("missing principal must not query investigation")


def test_list_error_does_not_disclose_internal_exception(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(inv_routes, "get_all_investigation_summaries", lambda tenant: (_ for _ in ()).throw(RuntimeError("sqlite secret path /private/db")))
    try:
        inv_routes.list_investigations(request_with_principal(SimpleNamespace(tenant_id="tenant-a")))
    except HTTPException as exc:
        assert exc.status_code == 500
        assert "sqlite secret path" not in str(exc.detail)
        assert "Internal server error" in str(exc.detail)
    else:
        raise AssertionError("expected sanitized HTTPException")


def test_single_error_does_not_disclose_internal_exception(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(inv_routes, "get_investigation", lambda *args: (_ for _ in ()).throw(RuntimeError("sqlite secret path /private/db")))
    try:
        inv_routes.get_single_investigation("INV-A", request_with_principal(SimpleNamespace(tenant_id="tenant-a")))
    except HTTPException as exc:
        assert exc.status_code == 500
        assert "sqlite secret path" not in str(exc.detail)
        assert "Internal server error" in str(exc.detail)
    else:
        raise AssertionError("expected sanitized HTTPException")
