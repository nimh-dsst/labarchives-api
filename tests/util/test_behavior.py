"""Unit tests for behavior enums."""

from __future__ import annotations


from labapi.util.types import InsertBehavior


def test_insert_behavior_enum_members():
    """Test InsertBehavior enum has correct members and values."""
    assert InsertBehavior.Replace.value == 0
    assert InsertBehavior.Ignore.value == 1
    assert InsertBehavior.Retain.value == 2
    assert InsertBehavior.Raise.value == 3


def test_insert_behavior_count():
    """Test InsertBehavior enum has exactly four members."""
    assert len(InsertBehavior) == 4
    members = list(InsertBehavior)
    assert InsertBehavior.Replace in members
    assert InsertBehavior.Ignore in members
    assert InsertBehavior.Retain in members
    assert InsertBehavior.Raise in members
