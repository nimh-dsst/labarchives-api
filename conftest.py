from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from io import BufferedIOBase
from typing import TYPE_CHECKING, Any, override
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
import requests

# from dotenv import load_dotenv
from lxml import etree

import labapi as LA
from labapi.tree.collection import Notebooks

# load_dotenv()


def pytest_configure(config: pytest.Config):
    config.addinivalue_line(
        "markers", "is_interactive: mark test as requiring interactive mode"
    )


def pytest_runtest_setup(item: pytest.Item):
    if "is_interactive" in item.keywords:
        if item.config.getoption("capture") != "no":
            pytest.skip("skipping interactive test in non-interactive mode")


class MockClient(LA.Client):
    """Mock client for testing without hitting the real API."""

    def __init__(self):
        super().__init__("https://test-labapi.test", "test", "test")
        self._api_response: list[etree.Element | Exception] = []
        self._api_logs: list[tuple[str | Sequence[str], dict[str, Any]]] = []

    @override
    def _signature(self, api_method: str, expiry: int) -> str:
        return f"signed:{api_method}:{expiry}"

    @override
    def _sign_url(
        self,
        url: str,
        api_method: str,
        expires_in: timedelta | datetime = timedelta(seconds=60),
    ) -> str:
        scheme, netloc, path, querystring, _f = urlsplit(url)
        query = dict(parse_qsl(querystring))

        if isinstance(expires_in, timedelta):
            expiry = round((datetime.fromtimestamp(0) + expires_in).timestamp() * 1000)
        else:
            expiry = round(expires_in.timestamp() * 1000)
        sig = self._signature(api_method, expiry)

        query["akid"] = self._akid
        query["expires"] = str(expiry)
        query["sig"] = sig

        return urlunsplit((scheme, netloc, path, urlencode(query), _f))

    @property
    def api_response(self):
        return self._api_response[0]

    @api_response.setter
    def api_response(self, value: str | Exception | etree.Element):
        if isinstance(value, str):
            value = etree.fromstring(bytes(value, encoding="utf-8"))

        self._api_response.append(value)

    @property
    def api_log(self):
        return self._api_logs.pop(0)

    def flush_responses(self):
        """Clears all queued API responses."""
        self._api_response.clear()

    def flush_logs(self):
        """Clears all recorded API logs."""
        self._api_logs.clear()

    def clear_log(self):
        self.flush_logs()

    @override
    def api_get(
        self,
        api_method_uri: str | Sequence[str],
        **kwargs: Any,
    ) -> etree.Element:
        self._api_logs.append((api_method_uri, kwargs))

        assert len(self._api_response) != 0, (
            "Invalid Mock Client State: Did not load API Response"
        )

        api_response = self._api_response.pop(0)

        if isinstance(api_response, Exception):
            raise api_response

        return api_response

    @override
    def raw_api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ) -> requests.Response:
        log_kwargs = {**kwargs}
        if not isinstance(body, BufferedIOBase):
            log_kwargs.update(body)

        self._api_logs.append((api_method_uri, log_kwargs))

        assert len(self._api_response) != 0, (
            "Invalid Mock Client State: Did not load API Response"
        )

        api_response = self._api_response.pop(0)

        if isinstance(api_response, Exception):
            raise api_response

        # Create a mock requests.Response object
        mock_response = requests.Response()
        mock_response.status_code = 200
        mock_response._content = etree.tostring(api_response)
        return mock_response


@pytest.fixture
def client():
    """Fixture providing a MockClient instance."""
    client = MockClient()
    yield client
    # Ensure all queued responses were consumed
    assert len(client._api_response) == 0, (
        f"Unused API responses in MockClient: {len(client._api_response)}"
    )
    # Ensure all API calls were verified (logs popped)
    assert len(client._api_logs) == 0, (
        f"Unverified API calls in MockClient: {len(client._api_logs)}"
    )


@pytest.fixture
def user(client: MockClient):
    """Fixture providing a logged-in User instance."""
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <users>
        <fullname>Test User 1</fullname>
        <id>testid1</id>
        <auto-login-allowed type="boolean">false</auto-login-allowed>
        <request>

        </request>
        <notebooks type="array">
            <notebook>
                <is-default type="boolean">true</is-default>
                <name>Test Notebook 1</name>
                <id>testnb1</id>
            </notebook>
            <notebook>
                <is-default type="boolean">true</is-default>
                <name>Test Notebook 3</name>
                <id>testnb2</id>
            </notebook>
            <notebook>
                <is-default type="boolean">true</is-default>
                <name>Test Notebook 3</name>
                <id>testnb3</id>
            </notebook>
        </notebooks>
    </users>
    """
    result = client.login("test_email@test.test", "test_authcode")
    assert client.api_log == (
        "users/user_access_info",
        {"login_or_email": "test_email@test.test", "password": "test_authcode"},
    )
    client.flush_logs()
    return result


@pytest.fixture
def notebooks(user: LA.User) -> Notebooks:
    """Fixture providing a Notebooks collection."""
    return user.notebooks


@pytest.fixture
def notebook(notebooks: Notebooks):
    """Fixture providing a single Notebook instance."""
    return notebooks[LA.Index.Id : "testnb1"]


@pytest.fixture
def new_notebook(client: MockClient, notebooks: Notebooks):
    """Fixture providing a newly created notebook."""
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <notebooks>
        <nbid>testnb4</nbid>
    </notebooks>
    """

    notebook = notebooks.create_notebook("Test Notebook 4")

    client.flush_logs()
    return notebook


def traverse_populate(node: LA.Notebook | LA.NotebookDirectory):
    """Helper function to recursively populate a notebook tree."""
    # Trigger population
    len(node)

    for _node in node.values():
        if isinstance(_node, LA.Notebook | LA.NotebookDirectory):
            traverse_populate(_node)


@pytest.fixture
def notebook_tree(client: MockClient, notebook: LA.Notebook) -> LA.Notebook:
    """Fixture providing a fully populated notebook tree structure."""
    notebook.refresh()

    # Level 0
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <tree-tools>
        <level-nodes type="array">
            <level-node>
                <is-page type="boolean">false</is-page>
                <tree-id>dir-1</tree-id>
                <display-text>Test Folder A</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
            <level-node>
                <is-page type="boolean">false</is-page>
                <tree-id>dir-2</tree-id>
                <display-text>Test Folder B</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
            <level-node>
                <is-page type="boolean">true</is-page>
                <tree-id>page-1</tree-id>
                <display-text>Test Page 1</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
        </level-nodes>
    </tree-tools>
    """

    # Dir 1
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <tree-tools>
        <level-nodes type="array">
            <level-node>
                <is-page type="boolean">true</is-page>
                <tree-id>page-1-1</tree-id>
                <display-text>Dir1 Test Page A</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
            <level-node>
                <is-page type="boolean">true</is-page>
                <tree-id>page-1-2</tree-id>
                <display-text>Dir1 Test Page B</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
        </level-nodes>
    </tree-tools>
    """

    # Dir 2
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <tree-tools>
        <level-nodes type="array">
            <level-node>
                <is-page type="boolean">false</is-page>
                <tree-id>dir-2-1</tree-id>
                <display-text>Dir2 Subfolder A</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
            <level-node>
                <is-page type="boolean">false</is-page>
                <tree-id>dir-2-2</tree-id>
                <display-text>Dir2 Subfolder B</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
            <level-node>
                <is-page type="boolean">true</is-page>
                <tree-id>page-2-1</tree-id>
                <display-text>Dir2 Test Page</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
        </level-nodes>
    </tree-tools>"""

    # Dir 2 Sub A
    client.api_response = """
    <tree-tools>
        <level-nodes type="array">
        </level-nodes>
    </tree-tools>
    """

    # Dir 2 Sub B
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <tree-tools>
        <level-nodes type="array">
            <level-node>
                <is-page type="boolean">false</is-page>
                <tree-id>dir-2-2-1</tree-id>
                <display-text>Dir2 Subfolder B Subfolder</display-text>
                <user-access>
                    <can-read type="boolean">true</can-read>
                    <can-write type="boolean">true</can-write>
                    <can-read-comments type="boolean">true</can-read-comments>
                    <can-write-comments type="boolean">true</can-write-comments>
                </user-access>
            </level-node>
        </level-nodes>
    </tree-tools>"""

    # Dir 2 Sub B Sub
    client.api_response = """
    <tree-tools>
        <level-nodes type="array">
        </level-nodes>
    </tree-tools>
    """

    traverse_populate(notebook)
    client.flush_logs()

    return notebook
