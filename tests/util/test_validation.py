"""Unit tests for node name validation helpers."""

from __future__ import annotations

import pytest

from labapi.util import validate_node_name


@pytest.mark.parametrize(
    "name",
    [
        "Experiment 1",
        ".. copy",
        "Folder.Name",
    ],
)
def test_validate_node_name_accepts_valid_names(name: str):
    """Test validate_node_name accepts names allowed by local path semantics."""
    validate_node_name(name)


@pytest.mark.parametrize(
    ("name", "match"),
    [
        ("", "cannot be empty"),
        ("   ", "cannot be only whitespace"),
        ("Parent/Child", 'cannot contain "/"'),
        ("..", "reserved for parent navigation"),
    ],
)
def test_validate_node_name_rejects_invalid_names(name: str, match: str):
    """Test validate_node_name rejects unsupported local path names."""
    with pytest.raises(ValueError, match=match):
        validate_node_name(name)
