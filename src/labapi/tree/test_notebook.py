"""Unit tests for Notebook class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from labapi import Notebook
from labapi.tree.collection import Notebooks
from labapi.util.notebookinit import NotebookInit
from labapi.user import User


class TestNotebookUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_notebook_initialization(self):
        """Test Notebook can be initialized with NotebookInit."""
        mock_user = Mock(spec=User)
        mock_notebooks = Mock(spec=Notebooks)

        init = NotebookInit(id="nb_test", name="Test Notebook", is_default=True)
        notebook = Notebook(init, mock_user, mock_notebooks)

        assert notebook.id == "nb_test"
        assert notebook.name == "Test Notebook"
        assert notebook.is_default is True

    def test_notebook_properties(self):
        """Test Notebook basic property accessors."""
        mock_user = Mock(spec=User)
        mock_notebooks = Mock(spec=Notebooks)

        init = NotebookInit(id="testnb1", name="Test Notebook 1", is_default=True)
        notebook = Notebook(init, mock_user, mock_notebooks)

        assert notebook.id == "testnb1"
        assert notebook.name == "Test Notebook 1"
        assert notebook.is_default is True

    def test_notebook_is_root(self):
        """Test Notebook is its own root."""
        mock_user = Mock(spec=User)
        mock_notebooks = Mock(spec=Notebooks)

        init = NotebookInit(id="testnb1", name="Test Notebook 1", is_default=True)
        notebook = Notebook(init, mock_user, mock_notebooks)

        assert notebook.root is notebook


class TestNotebookIntegration:
    """Integration tests with real objects and mocked API."""

    def test_notebook_name_setter(self, client, notebook: Notebook):
        """Test Notebook.name setter updates name via API."""
        # Mock API response
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <success>true</success>
        </notebooks>
        """

        # Update name
        notebook.name = "Updated Notebook Name"

        # Verify API call
        api_call = client.api_log
        assert api_call[0] == "notebooks/modify_notebook_info"
        assert api_call[1]["nbid"] == "testnb1"
        assert api_call[1]["name"] == "Updated Notebook Name"

        # Verify name was updated locally
        assert notebook.name == "Updated Notebook Name"

    def test_notebook_inserts_from_bottom(self, client, notebook: Notebook):
        """Test Notebook.inserts_from_bottom lazy loads from API."""
        # Mock API response
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <notebook>
                <id>testnb1</id>
                <add-entry-to-page-top type="boolean">false</add-entry-to-page-top>
            </notebook>
        </notebooks>
        """

        client.clear_log()

        # Access property (should trigger API call)
        result = notebook.inserts_from_bottom

        # Verify result (false means inserts from bottom = true)
        assert result is True

        # Verify API call
        api_call = client.api_log
        assert api_call[0] == "notebooks/notebook_info"
        assert api_call[1]["nbid"] == "testnb1"

    def test_notebook_inserts_from_bottom_caching(self, client, notebook: Notebook):
        """Test Notebook.inserts_from_bottom caches the result."""
        # Mock API response
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <notebook>
                <id>testnb1</id>
                <add-entry-to-page-top type="boolean">true</add-entry-to-page-top>
            </notebook>
        </notebooks>
        """

        # First access
        result1 = notebook.inserts_from_bottom
        assert result1 is False  # true means inserts from top, not bottom

        # Clear the API log
        client.clear_log()

        # Second access should not make another API call
        result2 = notebook.inserts_from_bottom
        assert result2 is False

        # Verify no second API call was made (would raise if api_log is empty)
        with pytest.raises(IndexError):
            client.api_log
