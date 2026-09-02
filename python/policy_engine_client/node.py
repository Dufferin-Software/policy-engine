# Copyright (c) Peter Morrow

"""The slice of a test node these clients actually use."""

from typing import Protocol


class Node(Protocol):
    """A host the clients can run shell commands on over SSH.

    Structural, so the clients stay independent of whoever supplies the node.
    netsim.testkit.node.Node satisfies it, and so does any other handle with
    the same three members.
    """

    name: str

    def ssh_command(self, cmd: str, timeout: int = 10) -> str: ...

    def ssh_command_with_stdin(
        self, cmd: str, stdin_data: str, timeout: int = 10
    ) -> str: ...
