"""Provider-neutral mail gateway adapter contract; no live actions by default."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

GatewayAction = Literal["ALLOW", "REVIEW", "QUARANTINE"]
GatewayOutcome = Literal["APPLIED", "FAILED", "OBSERVED"]


class GatewayAdapterNotConfigured(RuntimeError):
    """Raised when enforcement is requested without a configured provider adapter."""


@dataclass(frozen=True)
class GatewayActionResult:
    action: GatewayAction
    outcome: GatewayOutcome
    idempotency_key: str
    gateway_message_id: str | None = None
    reason_code: str | None = None


@runtime_checkable
class MailGatewayAdapter(Protocol):
    """Implementations must make actions idempotent and return provider-confirmed outcomes."""

    @property
    def name(self) -> str: ...

    @property
    def configured(self) -> bool: ...

    def apply_action(
        self,
        *,
        event_id: str,
        message_id: str,
        action: GatewayAction,
        idempotency_key: str,
    ) -> GatewayActionResult: ...


class UnconfiguredMailGatewayAdapter:
    """Fail-closed placeholder: never claims that a mail action was applied."""

    name = "unconfigured"
    configured = False

    def apply_action(
        self,
        *,
        event_id: str,
        message_id: str,
        action: GatewayAction,
        idempotency_key: str,
    ) -> GatewayActionResult:
        raise GatewayAdapterNotConfigured(
            "No vendor mail gateway adapter is configured; no action was attempted."
        )


def get_mail_gateway_adapter() -> MailGatewayAdapter:
    """Return the safe default until an explicitly configured provider is implemented."""
    return UnconfiguredMailGatewayAdapter()
