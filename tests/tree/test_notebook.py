"""Unit tests for Notebook class."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

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
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <success>true</success>
        </notebooks>
        """

        notebook.name = "Updated Notebook Name"

        api_call = client.api_log
        assert api_call[0] == "notebooks/modify_notebook_info"
        assert api_call[1]["nbid"] == "testnb1"
        assert api_call[1]["name"] == "Updated Notebook Name"
        assert notebook.name == "Updated Notebook Name"

    def test_notebook_name_setter_rejects_invalid_name_without_api_request(
        self, client, notebook: Notebook
    ):
        """Test Notebook.name rejects invalid names before any API call."""
        client.clear_log()

        with pytest.raises(ValueError, match='cannot contain "/"'):
            notebook.name = "Bad/Name"

        assert client._api_logs == []

    def test_notebook_inserts_from_bottom(self, client, notebook: Notebook):
        """Test Notebook.inserts_from_bottom lazy loads from API."""
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <notebook>
                <id>testnb1</id>
                <add-entry-to-page-top type="boolean">false</add-entry-to-page-top>
            </notebook>
        </notebooks>
        """

        client.clear_log()

        result = notebook.inserts_from_bottom

        assert result is True

        api_call = client.api_log
        assert api_call[0] == "notebooks/notebook_info"
        assert api_call[1]["nbid"] == "testnb1"

    def test_notebook_inserts_from_bottom_caching(self, client, notebook: Notebook):
        """Test Notebook.inserts_from_bottom caches the result."""
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <notebooks>
            <notebook>
                <id>testnb1</id>
                <add-entry-to-page-top type="boolean">true</add-entry-to-page-top>
            </notebook>
        </notebooks>
        """

        result1 = notebook.inserts_from_bottom
        client.clear_log()

        result2 = notebook.inserts_from_bottom

        assert result1 is result2
