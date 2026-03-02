"""Unit tests for NotebookInit dataclass."""

from __future__ import annotations

import pytest

from labapi.util.notebookinit import NotebookInit


def test_notebookinit_creation():
    """Test NotebookInit can be created with required fields."""
    notebook_init = NotebookInit(
        id="test_id_123",
        name="Test Notebook",
        is_default=True,
    )

    assert notebook_init.id == "test_id_123"
    assert notebook_init.name == "Test Notebook"
    assert notebook_init.is_default is True


def test_notebookinit_fields():
    """Test NotebookInit fields can be accessed and modified."""
    notebook_init = NotebookInit(
        id="nb_001",
        name="My Notebook",
        is_default=False,
    )

    # Test field access
    assert notebook_init.id == "nb_001"
    assert notebook_init.name == "My Notebook"
    assert notebook_init.is_default is False

    # Test field modification (dataclasses are mutable by default)
    notebook_init.name = "Updated Notebook"
    assert notebook_init.name == "Updated Notebook"

    notebook_init.is_default = True
    assert notebook_init.is_default is True


def test_notebookinit_equality():
    """Test NotebookInit equality comparison."""
    nb1 = NotebookInit(id="nb_001", name="Notebook 1", is_default=True)
    nb2 = NotebookInit(id="nb_001", name="Notebook 1", is_default=True)
    nb3 = NotebookInit(id="nb_002", name="Notebook 2", is_default=False)

    assert nb1 == nb2
    assert nb1 != nb3
