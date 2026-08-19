import logging

from policy_engine_client.engine.cli.client import IngressMode

logger = logging.getLogger(__name__)


class TestEgressAttachment:
    """Tests for egress program attachment and detachment."""

    def test_attach_egress(self, policy_client, server_interface):
        """Test attaching egress program to an interface."""
        iface_name = server_interface.if_name

        # Attach egress
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to attach egress: {result.message}"

        # Verify attachment
        interfaces = policy_client.list_interfaces()
        attached = [
            i
            for i in interfaces
            if i.interface == iface_name and i.direction == "egress"
        ]
        assert len(attached) == 1, f"Interface {iface_name} should have egress attached"
        logger.info(f"Egress attached: {attached[0]}")

        # Check server status
        status = policy_client.status()
        assert status.program_attached, "program_attached should be True"

        # Cleanup
        policy_client.detach_egress(iface_name)

    def test_detach_egress(self, policy_client, server_interface):
        """Test detaching egress program from an interface."""
        iface_name = server_interface.if_name

        # First attach
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to attach egress: {result.message}"

        # Then detach
        result = policy_client.detach_egress(iface_name)
        assert result.success, f"Failed to detach egress: {result.message}"

        # Verify detachment
        interfaces = policy_client.list_interfaces()
        attached = [
            i
            for i in interfaces
            if i.interface == iface_name and i.direction == "egress"
        ]
        assert len(attached) == 0, f"Interface {iface_name} should have egress detached"

    def test_attach_both_ingress_and_egress(self, policy_client, server_interface):
        """Test attaching both ingress and egress programs to the same interface."""
        iface_name = server_interface.if_name

        # Attach ingress
        result = policy_client.attach_ingress(iface_name, IngressMode.AUTO)
        assert result.success, f"Failed to attach ingress: {result.message}"

        # Attach egress
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to attach egress: {result.message}"

        # Verify both are attached
        interfaces = policy_client.list_interfaces()
        ingress_attached = [
            i
            for i in interfaces
            if i.interface == iface_name and i.direction == "ingress"
        ]
        egress_attached = [
            i
            for i in interfaces
            if i.interface == iface_name and i.direction == "egress"
        ]
        assert len(ingress_attached) == 1, "Ingress should be attached"
        assert len(egress_attached) == 1, "Egress should be attached"

        # Cleanup with detach all
        result = policy_client.detach_all()
        assert result.success, f"Failed to detach all: {result.message}"

        interfaces = policy_client.list_interfaces()
        assert len(interfaces) == 0, "All interfaces should be detached"

    def test_detach_all_removes_egress(self, policy_client, server_interface):
        """Test that detach_all removes egress attachments."""
        iface_name = server_interface.if_name

        # Attach egress
        policy_client.attach_egress(iface_name)

        # Detach all
        result = policy_client.detach_all()
        assert result.success, f"Failed to detach all: {result.message}"

        # Verify
        interfaces = policy_client.list_interfaces()
        assert len(interfaces) == 0, "All interfaces should be detached"
