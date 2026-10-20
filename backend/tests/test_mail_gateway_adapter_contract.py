import unittest

from services.mail_gateway.adapter import (
    GatewayAdapterNotConfigured,
    UnconfiguredMailGatewayAdapter,
    get_mail_gateway_adapter,
)


class MailGatewayAdapterContractTests(unittest.TestCase):
    def test_default_adapter_is_explicitly_unconfigured(self):
        adapter = get_mail_gateway_adapter()
        self.assertIsInstance(adapter, UnconfiguredMailGatewayAdapter)
        self.assertFalse(adapter.configured)
        self.assertEqual(adapter.name, "unconfigured")

    def test_unconfigured_adapter_never_claims_action_was_applied(self):
        adapter = get_mail_gateway_adapter()
        with self.assertRaisesRegex(GatewayAdapterNotConfigured, "no action was attempted"):
            adapter.apply_action(
                event_id="event-test",
                message_id="message-test",
                action="QUARANTINE",
                idempotency_key="idem-test",
            )


if __name__ == "__main__":
    unittest.main()
