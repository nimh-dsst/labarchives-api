"""Behavior Enumerations Module.

This module defines enumeration classes that specify behaviors for various
operations within the LabArchives API, such as node insertion and conflict
resolution.
"""

from enum import Enum


class InsertBehavior(Enum):
    """Enumeration of behaviors when inserting a node that already exists."""

    Replace = 0
    """Delete the existing node(s) and create a new one."""
    Ignore = 1
    """Just create a new node anyways."""
    Retain = 2
    """Keep the existing node and return it."""
    Raise = 3
    """Raise a RuntimeError if the node already exists."""
