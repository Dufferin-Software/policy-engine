import logging

logger = logging.getLogger(__name__)


class TestEgressAttachmentNegative:
    """Negative tests for egress attachment."""

    def test_attach_egress_nonexistent_interface(self, policy_client):
        """Test attaching egress to a non-existent interface fails gracefully."""
        result = policy_client.attach_egress("nonexistent0")
        assert not result.success, (
            "Should fail to attach egress to non-existent interface"
        )
        logger.info(f"Expected failure: {result.message}")

    def test_detach_egress_not_attached(self, policy_client, server_interface):
        """Test detaching egress when not attached returns appropriate response."""
        # Ensure nothing is attached
        policy_client.detach_all()

        result = policy_client.detach_egress(server_interface.if_name)
        logger.info(
            f"Detach egress when not attached: success={result.success}, msg={result.message}"
        )

    def test_double_attach_egress(self, policy_client, server_interface):
        """Test attaching egress twice to same interface."""
        iface_name = server_interface.if_name

        result1 = policy_client.attach_egress(iface_name)
        assert result1.success, f"First egress attach should succeed: {result1.message}"

        try:
            result2 = policy_client.attach_egress(iface_name)
            logger.info(
                f"Double egress attach: success={result2.success}, msg={result2.message}"
            )
        finally:
            policy_client.detach_egress(iface_name)
