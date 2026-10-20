from services.response_execution.engine import transition_response
from services.response_verification.engine import verify_response


def test_verification_engine_returns_structured_result_without_actions():
    result = verify_response({"response_id": "resp-test", "status": "EXECUTING", "recommended_actions": []})

    assert result["success"] is True
    assert result["response_id"] == "resp-test"
    assert result["simulated"] is True
    assert result["persistence"] is False
    assert result["execution_side_effect"] is False
    assert {item["check_id"] for item in result["checks"]} >= {
        "ACTION_COMPLETION", "NO_SIDE_EFFECT"
    }


def test_verification_rejects_non_mapping_response_safely():
    result = verify_response(None)

    assert result["success"] is False
    assert result["verification_status"] == "NOT_READY"
    assert result["execution_side_effect"] is False


def test_response_execution_invalid_operation_fails_closed():
    source = {"response_id": "resp-test", "status": "PLANNED", "recommended_actions": []}
    result = transition_response(source, "DELETE", actor="analyst", reason="test")

    assert result["success"] is False
    assert result["persistence"] is False
    assert result["simulated"] is True
    assert result["execution_side_effect"] is False
    assert source["status"] == "PLANNED"


def test_string_false_observation_cannot_be_treated_as_success():
    response = {
        "response_id": "resp-observation-test",
        "status": "VERIFIED",
        "recommended_actions": [
            {"action_id": "act-1", "action_type": "QUARANTINE", "status": "EXECUTED"}
        ],
    }
    result = verify_response(
        response,
        {"action_results": {"act-1": {"success": "false", "evidence": "provider reported failure"}}},
    )

    assert result["action_results"][0]["observed_success"] is False
    assert result["action_results"][0]["verified"] is False
    assert result["verification_status"] == "FAILED"
    assert result["close_recommended"] is False


def test_unrelated_ioc_observation_does_not_satisfy_verification_or_close():
    response = {
        "response_id": "resp-ioc-test",
        "status": "VERIFIED",
        "iocs": ["evil.example"],
        "recommended_actions": [
            {"action_id": "act-1", "action_type": "QUARANTINE", "status": "EXECUTED"}
        ],
    }
    result = verify_response(
        response,
        {
            "action_results": {"act-1": {"success": True, "evidence": "provider confirms action"}},
            "ioc_observations": {"unrelated.example": {"status": "BLOCKED", "evidence": "unrelated IOC"}},
        },
    )

    assert result["ioc_results"]["unknown"] == ["evil.example"]
    assert result["verification_status"] == "PARTIAL"
    assert result["close_recommended"] is False
    ioc_check = next(item for item in result["checks"] if item["check_id"] == "IOC_OBSERVATIONS")
    assert ioc_check["passed"] is False


def test_response_management_routes_bind_to_their_intended_handlers():
    from main import app

    routes = {
        route.path: route.endpoint.__name__
        for route in app.routes
        if getattr(route, "path", None) in {
            "/api/response-management/transition",
            "/api/response-management/verification",
            "/api/recommendations/build",
        }
    }

    assert routes["/api/response-management/transition"] == "transition_response_plan"
    assert routes["/api/response-management/verification"] == "verify_response_plan"
    assert routes["/api/recommendations/build"] == "build_recommendations_api"


def test_transition_audit_actor_comes_from_authenticated_principal():
    import asyncio
    from types import SimpleNamespace
    from starlette.requests import Request
    from main import transition_response_plan

    scope = {
        "type": "http", "method": "POST", "path": "/api/response-management/transition",
        "headers": [], "query_string": b"", "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345), "scheme": "http", "http_version": "1.1",
        "asgi": {"version": "3.0"}, "state": {},
    }
    request = Request(scope)
    request.state.principal = SimpleNamespace(subject_id="authenticated-analyst")
    result = asyncio.run(transition_response_plan({
        "response": {
            "response_id": "resp-audit-test", "status": "PLANNED",
            "recommended_actions": [{"action_id": "act-1", "approval_status": "PENDING"}],
        },
        "operation": "APPROVE", "actor": "forged-admin", "reason": "reviewed",
    }, request))

    assert result["success"] is True
    assert result["response_execution"]["response"]["audit"][-1]["actor"] == "authenticated-analyst"
