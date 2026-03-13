"""Unit tests for indexing utilities."""

from __future__ import annotations

from labapi.util.types import Index


def test_index_enum_members():
    """Test Index enum has correct members."""
    assert hasattr(Index, "Id")
    assert hasattr(Index, "Name")
    assert Index.Id.value == "id"
    assert Index.Name.value == "name"


def test_index_enum_count():
    """Test Index enum has exactly two members."""
    assert len(Index) == 2
    members = list(Index)
    assert Index.Id in members
    assert Index.Name in members
