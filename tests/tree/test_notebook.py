"""Unit tests for Notebook class."""

from __future__ import annotations

from unittest.mock import Mock

from labapi import Notebook
from labapi.tree.collection import Notebooks
from labapi.user import User
from labapi.util.types import NotebookInit


class TestNotebookUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_notebook_properties(self):
        """Test Notebook stores id, name, is_default, and is its own root."""
        mock_user = Mock(spec=User)
        mock_notebooks = Mock(spec=Notebooks)

        init = NotebookInit(id="nb_test", name="Test Notebook", is_default=True)
        notebook = Notebook(init, mock_user, mock_notebooks)

        assert notebook.id == "nb_test"
        assert notebook.name == "Test Notebook"
        assert notebook.is_default is True
        assert notebook.root is notebook


class TestNotebookIntegration:
    """Integration tests with real objects and mocked API."""

    def test_notebook_name_setter(self, client, notebook: Notebook):
        """Test Notebook.name setter updates name via API."""
        client.api_response = client.xml(
            "notebooks",
            client.xml("success", True),
        )

        notebook.name = "Updated Notebook Name"

        api_call = client.pop_api_call()
        assert api_call[0] == "notebooks/modify_notebook_info"
        assert api_call[1]["nbid"] == "testnb1"
        assert api_call[1]["name"] == "Updated Notebook Name"
        assert notebook.name == "Updated Notebook Name"
