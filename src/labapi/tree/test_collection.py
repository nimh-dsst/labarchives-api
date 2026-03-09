"""Unit tests for Notebooks collection class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi import Index, Notebook
from labapi.tree.collection import Notebooks
from labapi.user import User
from labapi.util.notebookinit import NotebookInit


class TestNotebooksUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_notebooks_len(self):
        """Test Notebooks.__len__ returns count."""
        mock_user = Mock(spec=User)
        notebooks_init = [
            NotebookInit(id="nb1", name="Notebook 1", is_default=True),
            NotebookInit(id="nb2", name="Notebook 2", is_default=False),
        ]
        notebooks = Notebooks(notebooks_init, mock_user)

        assert len(notebooks) == 2

    def test_notebooks_getitem_by_id_index(self):
        """Test Notebooks.__getitem__ with Index.Id slice."""
        mock_user = Mock(spec=User)
        notebooks_init = [NotebookInit(id="nb1", name="Test", is_default=True)]
        notebooks = Notebooks(notebooks_init, mock_user)

        notebook = notebooks[Index.Id : "nb1"]

        assert isinstance(notebook, Notebook)
        assert notebook.id == "nb1"

    def test_notebooks_getitem_by_name_index(self):
        """Test Notebooks.__getitem__ with Index.Name slice returns list."""
        mock_user = Mock(spec=User)
        notebooks_init = [
            NotebookInit(id="nb1", name="Test", is_default=True),
            NotebookInit(id="nb2", name="Test", is_default=False),
        ]
        notebooks = Notebooks(notebooks_init, mock_user)

        result = notebooks[Index.Name : "Test"]

        assert isinstance(result, list)
        assert len(result) == 2

    def test_notebooks_getitem_by_name_empty(self):
        """Test Notebooks.__getitem__ with Index.Name returns empty list if not found."""
        mock_user = Mock(spec=User)
        notebooks_init = [NotebookInit(id="nb1", name="Test", is_default=True)]
        notebooks = Notebooks(notebooks_init, mock_user)

        result = notebooks[Index.Name : "Nonexistent"]

        assert result == []

    def test_notebooks_getitem_by_string_raises(self):
        """Test Notebooks.__getitem__ with string raises KeyError if not found."""
        mock_user = Mock(spec=User)
        notebooks_init = [NotebookInit(id="nb1", name="Test", is_default=True)]
        notebooks = Notebooks(notebooks_init, mock_user)

        with pytest.raises(
            KeyError, match='Notebook with name "Nonexistent" not found'
        ):
            notebooks["Nonexistent"]

    def test_notebooks_getitem_invalid_key_type_raises(self):
        """Test Notebooks.__getitem__ raises TypeError for unsupported key types."""
        mock_user = Mock(spec=User)
        notebooks_init = [NotebookInit(id="nb1", name="Test", is_default=True)]
        notebooks = Notebooks(notebooks_init, mock_user)

        with pytest.raises(TypeError, match="Invalid key type"):
            notebooks[123]  # pyright: ignore[reportArgumentType]

    def test_notebooks_iter(self):
        """Test Notebooks.__iter__ returns iterator over names."""
        mock_user = Mock(spec=User)
        notebooks_init = [
            NotebookInit(id="nb1", name="Notebook 1", is_default=True),
            NotebookInit(id="nb2", name="Notebook 2", is_default=False),
        ]
        notebooks = Notebooks(notebooks_init, mock_user)

        names = list(notebooks)

        assert names == ["Notebook 1", "Notebook 2"]

    def test_notebooks_values(self):
        """Test Notebooks.values returns notebook objects."""
        mock_user = Mock(spec=User)
        notebooks_init = [
            NotebookInit(id="nb1", name="Notebook 1", is_default=True),
            NotebookInit(id="nb2", name="Notebook 2", is_default=False),
        ]
        notebooks = Notebooks(notebooks_init, mock_user)

        values = list(notebooks.values())

        assert len(values) == 2
        assert all(isinstance(nb, Notebook) for nb in values)


class TestNotebooksIntegration:
    """Integration tests with real objects and mocked API."""

    def test_notebooks_getitem_by_string(self, notebooks: Notebooks):
        """Test Notebooks.__getitem__ with string name."""
        notebook = notebooks["Test Notebook 1"]

        assert isinstance(notebook, Notebook)
        assert notebook.name == "Test Notebook 1"
        assert notebook.id == "testnb1"

    def test_notebooks_getitem_by_id(self, notebooks: Notebooks):
        """Test Notebooks.__getitem__ with Index.Id slice."""
        notebook = notebooks[Index.Id : "testnb2"]

        assert isinstance(notebook, Notebook)
        assert notebook.id == "testnb2"

    def test_notebooks_getitem_by_name(self, notebooks: Notebooks):
        """Test Notebooks.__getitem__ with Index.Name slice."""
        notebooks_list = notebooks[Index.Name : "Test Notebook 3"]

        assert isinstance(notebooks_list, list)
        assert len(notebooks_list) == 2
        assert notebooks_list[0].id == "testnb2"
        assert notebooks_list[1].id == "testnb3"

    def test_notebooks_create_notebook(self, client, notebooks: Notebooks):
        """Test Notebooks.create_notebook creates a new notebook."""
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <nbid>new_nb_id</nbid>
        </notebooks>
        """

        new_notebook = notebooks.create_notebook("New Notebook")

        assert isinstance(new_notebook, Notebook)
        assert new_notebook.id == "new_nb_id"
        assert new_notebook.name == "New Notebook"
        assert new_notebook.is_default is False

        assert len(notebooks) == 4
        assert notebooks[Index.Id : "new_nb_id"] is new_notebook

        api_call = client.api_log
        assert api_call[0] == "notebooks/create_notebook"
        assert api_call[1]["name"] == "New Notebook"
        assert api_call[1]["initial_folders"] == "Empty"

    def test_notebooks_create_notebook_duplicate_id_raises(
        self, client, notebooks: Notebooks
    ):
        """Test Notebooks.create_notebook raises RuntimeError if API returns existing ID."""
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <nbid>testnb1</nbid>
        </notebooks>
        """

        with pytest.raises(RuntimeError, match="API returned an existing notebook ID"):
            notebooks.create_notebook("Duplicate")
        client.clear_log()
