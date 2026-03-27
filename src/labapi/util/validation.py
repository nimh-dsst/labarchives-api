"""Validation helpers for local LabArchives naming semantics."""

from __future__ import annotations


def validate_node_name(name: str) -> None:
    """Validate a single node name against local path semantics.

    This helper only enforces client-side constraints implied by local path
    handling. It does not attempt to mirror all server-side LabArchives naming
    rules.

    :param name: A single node name or path segment.
    :raises ValueError: If the name is empty, whitespace-only, contains '/',
        or equals '..'.
    """
    if name == "":
        raise ValueError("Node name cannot be empty")
    if name.strip() == "":
        raise ValueError("Node name cannot be only whitespace")
    if "/" in name:
        raise ValueError('Node name cannot contain "/"')
    if name == "..":
        raise ValueError('Node name ".." is reserved for parent navigation')
