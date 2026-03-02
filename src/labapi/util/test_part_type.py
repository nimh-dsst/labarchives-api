"""Unit tests for part type utilities."""

from __future__ import annotations

import pytest

from labapi.util.part_type import (
    get_normalized_part_type,
    is_part_type,
    is_valid_part_type,
    serialize_part_type,
)


# Tests for get_normalized_part_type
@pytest.mark.parametrize(
    "input_type,expected",
    [
        ("attachment", "attachment"),
        ("Attachment", "attachment"),
        ("ATTACHMENT", "attachment"),
        ("  attachment  ", "attachment"),
        ("  ATTACHMENT  ", "attachment"),
        ("text entry", "text entry"),
        ("TEXT ENTRY", "text entry"),
        ("Text Entry", "text entry"),
        ("  Text Entry  ", "text entry"),
        ("heading", "heading"),
        ("HEADING", "heading"),
        ("  Heading  ", "heading"),
        ("plain text entry", "plain text entry"),
        ("PLAIN TEXT ENTRY", "plain text entry"),
        ("widget entry", "widget entry"),
        ("Widget Entry", "widget entry"),
    ],
)
def test_get_normalized_part_type(input_type: str, expected: str):
    """Test get_normalized_part_type with various inputs."""
    assert get_normalized_part_type(input_type) == expected


# Tests for is_part_type
@pytest.mark.parametrize(
    "part_type",
    [
        "attachment",
        "plain text entry",
        "heading",
        "text entry",
        "widget entry",
        "sketch entry",
        "reference entry",
        "equation entry",
        "assignment entry",
    ],
)
def test_is_part_type_valid(part_type: str):
    """Test is_part_type returns True for recognized part types."""
    assert is_part_type(part_type) is True


@pytest.mark.parametrize(
    "part_type",
    [
        "Attachment",  # Not normalized
        "ATTACHMENT",  # Not normalized
        "unknown type",
        "invalid",
        "",
        "text",
        "entry",
        "Attachment ",  # Not normalized
        " attachment",  # Not normalized
    ],
)
def test_is_part_type_invalid(part_type: str):
    """Test is_part_type returns False for unrecognized or non-normalized types."""
    assert is_part_type(part_type) is False


# Tests for is_valid_part_type
@pytest.mark.parametrize(
    "part_type",
    [
        "attachment",
        "plain text entry",
        "heading",
        "text entry",
        "widget entry",
    ],
)
def test_is_valid_part_type_implemented(part_type: str):
    """Test is_valid_part_type returns True for implemented part types."""
    assert is_valid_part_type(part_type) is True


@pytest.mark.parametrize(
    "part_type",
    [
        "sketch entry",  # Recognized but not implemented
        "reference entry",  # Recognized but not implemented
        "equation entry",  # Recognized but not implemented
        "assignment entry",  # Recognized but not implemented
        "unknown type",  # Not recognized
        "Attachment",  # Not normalized
        "",
    ],
)
def test_is_valid_part_type_not_implemented(part_type: str):
    """Test is_valid_part_type returns False for non-implemented or invalid types."""
    assert is_valid_part_type(part_type) is False


# Tests for serialize_part_type
@pytest.mark.parametrize(
    "input_type,expected",
    [
        # Special case: attachment -> Attachment
        ("attachment", "Attachment"),
        ("Attachment", "Attachment"),
        ("ATTACHMENT", "Attachment"),
        ("  attachment  ", "Attachment"),
        # Other types return original (not normalized form)
        ("text entry", "text entry"),
        ("TEXT ENTRY", "TEXT ENTRY"),
        ("  text entry  ", "  text entry  "),
        ("heading", "heading"),
        ("HEADING", "HEADING"),
        ("plain text entry", "plain text entry"),
        ("widget entry", "widget entry"),
    ],
)
def test_serialize_part_type(input_type: str, expected: str):
    """Test serialize_part_type handles special mappings and returns original for unmapped types."""
    assert serialize_part_type(input_type) == expected


def test_serialize_part_type_unknown():
    """Test serialize_part_type with unknown part type."""
    # Unknown types are returned as-is (original input, not normalized)
    assert serialize_part_type("unknown type") == "unknown type"
    assert serialize_part_type("UNKNOWN TYPE") == "UNKNOWN TYPE"
