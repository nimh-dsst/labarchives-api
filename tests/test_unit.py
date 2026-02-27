from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, override
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
import requests
from dotenv import load_dotenv
from lxml import etree

import labapi as LA
from labapi.util.extract import _flatten_dict, to_bool

load_dotenv()

if TYPE_CHECKING:
    from io import BufferedIOBase


class MockNotebooks:
    # This mock is minimal, add methods/properties as needed by tests

    @property
    def _user(self):
        return None  # Or a mock user if needed


class MockClient(LA.Client):
    def __init__(self):
        super().__init__("https://test-labapi.test", "test", "test")
        self._api_response: list[etree.Element | Exception] = []
        self._api_logs: list[tuple[str | Sequence[str], Mapping[str, Any]]] = []

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

    @override
    def api_get(
        self,
        api_method_uri: str | Sequence[str],
        **kwargs: Any,
    ) -> etree.Element:  # XXX need ability to assert what this was called with
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
        self._api_logs.append((api_method_uri, kwargs))

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
    return MockClient()


@pytest.fixture
def user(client: MockClient):
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
    return result


@pytest.fixture
def notebooks(user: LA.User):
    return user.notebooks


@pytest.fixture
def notebook(notebooks: LA.Notebooks):
    return notebooks[LA.Index.Id : "testnb1"]


@pytest.fixture
def new_notebook(client: MockClient, notebooks: LA.Notebooks):
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <notebooks>
        <nbid>testnb4</nbid>
    </notebooks>
    """

    notebook = notebooks.create_notebook("Test Notebook 4")

    client.api_log  # NOTE this looks ugly but it pops the last api call
    return notebook


def traverse_populate(node: LA.NotebookTreeNode | LA.Notebook):
    for _node in node.keys():
        if isinstance(_node, Sequence):
            raise ValueError("Iter did not return iterator over ids")

        if isinstance(_node, LA.NotebookTreeNode | LA.Notebook):
            traverse_populate(_node)


@pytest.fixture
def notebook_tree(client: MockClient, notebook: LA.Notebook) -> LA.Notebook:
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

    # for _ in range(5):
    #     print(client.api_log)

    return notebook


@pytest.mark.parametrize(
    "val,prefix,expected",
    [
        # Single-level, no prefix
        (
            {"a": str, "b": int},
            "",
            {"/a": str, "/b": int},
        ),
        # Nested, no prefix
        (
            {"a": {"b": int, "c": str}},
            "",
            {"/a/b": int, "/a/c": str},
        ),
        # Nested with prefix
        (
            {"a": {"b": int}, "c": str},
            "root",
            {"root/a/b": int, "root/c": str},
        ),
        # Deeper nesting
        (
            {"a": {"b": {"c": str}}},
            "",
            {"/a/b/c": str},
        ),
        # Empty dict at leaf
        ({"a": {"b": {"c": {}}}}, "", {}),
    ],
)
def test_flatten_dict_success(
    val: LA.util.extract.EtreeExtractorDict,
    prefix: str,
    expected: dict[str, Callable[[Any], Any]],
):
    assert _flatten_dict(val, prefix) == expected  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "val, prefix",
    [
        ({"": {"b": int}}, ""),  # Empty key
    ],
)
def test_flatten_dict_value_error(val: LA.util.extract.EtreeExtractorDict, prefix: str):
    with pytest.raises(ValueError):
        _flatten_dict(val, prefix)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "s,expected",
    [
        ("true", True),
        ("TRUE", True),
        ("True", True),
        ("false", False),
        ("FALSE", False),
        ("False", False),
        ("tRuE", True),
        ("fAlSe", False),
    ],
)
def test_to_bool_success(s: str, expected: bool):
    assert to_bool(s) is expected


@pytest.mark.parametrize(
    "s",
    [
        "",
        "0",
        "1",
        "yes",
        "no",
        "truthy",
        " falsE ",  # note: your current implementation does not strip
        " true ",  # note: your current implementation does not strip
        "none",
    ],
)
def test_to_bool_invalid_raises(s: str):
    with pytest.raises(ValueError, match=r"Cannot convert '.*' to bool"):
        to_bool(s)


@pytest.mark.parametrize(
    "api_method,kwargs",
    [
        ("tests/get_id", {}),
        (["tests", "get_id"], {}),
        ("tests/get_id", {"test_item": "1"}),
        (["tests", "get_id"], {"test_item": "1"}),
    ],
)
def test_user__api_get(
    client: MockClient,
    user: LA.User,
    api_method: str | Sequence[str],
    kwargs: Mapping[str, Any],
):
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <test>
        <id>1</id>
    </test>
    """

    expected_api_response = client.api_response

    assert user.api_get(api_method, **kwargs) == expected_api_response

    kwargs_with_uid = dict(kwargs.items())
    kwargs_with_uid["uid"] = user._id  # pyright: ignore[reportPrivateUsage]

    assert client.api_log == (api_method, kwargs_with_uid)


def test_user__get_max_upload_size(client: MockClient, user: LA.User):
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <users>
        <max-file-size type="integer">20</max-file-size>
    </users>
    """

    assert user.get_max_upload_size() == 20


def test_notebooks_initialize(notebooks: LA.Notebooks):
    assert len(notebooks) == 3, "Did not Initialize right number of notebooks"
    for i in notebooks:
        assert i in ("Test Notebook 1", "Test Notebook 3")


def test_notebooks__indexing(notebooks: LA.Notebooks):
    assert notebooks[LA.Index.Name : "Test Notebook 1"] == [
        notebooks[LA.Index.Id : "testnb1"],
    ]
    assert notebooks[LA.Index.Name : "Test Notebook 3"] == [
        notebooks[LA.Index.Id : "testnb2"],
        notebooks[LA.Index.Id : "testnb3"],
    ]
    assert notebooks[LA.Index.Name : "Test Notebook 3"] == [
        notebooks[LA.Index.Id : "testnb2"],
        notebooks[LA.Index.Id : "testnb3"],
    ]
    assert notebooks[LA.Index.Name : "AAA"] == []


def test_notebooks_indexing_no_notebook(notebooks: LA.Notebooks):
    with pytest.raises(KeyError):
        notebooks["AAAA"]


@pytest.mark.parametrize(
    "nbid",
    [
        "testnb4",
        "",
        "1",
        # "testnb2" # XXX See create_notebook() in main
    ],
)
def test_notebooks__create_notebook(
    client: MockClient, notebooks: LA.Notebooks, nbid: str
):
    client.api_response = f"""<?xml version="1.0" encoding="UTF-8"?>
    <notebooks>
        <nbid>{nbid}</nbid>
    </notebooks>
    """

    notebook = notebooks.create_notebook("Test Notebook 4")
    assert client.api_log[0] == "notebooks/create_notebook"

    assert notebook.id == nbid


def test_notebook__properties(notebook: LA.Notebook):
    assert notebook.id == "testnb1"
    assert notebook.name == "Test Notebook 1"
    assert notebook.is_default


def test_notebook__inserts_from_bottom(client: MockClient, notebook: LA.Notebook):
    client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
    <notebooks>
        <notebook>
            <id>testnb1</id>
            <add-entry-to-page-top type="boolean">false</add-entry-to-page-top>
        </notebook>
    </notebooks>"""

    assert notebook.inserts_from_bottom
    assert client.api_log[0] == "notebooks/notebook_info"


def test_tree_traversal(notebook: LA.Notebook, notebook_tree: LA.NotebookDirectory):
    k = notebook_tree[LA.Index.Id : "dir-1"]
    assert isinstance(k, LA.NotebookDirectory)
    assert isinstance(k[LA.Index.Id : "page-1-1"], LA.NotebookPage)
    assert k.parent == notebook

    k = notebook_tree[LA.Index.Name : "Test Folder B"][0]
    assert isinstance(k, LA.NotebookDirectory)

    print(k.values())

    k = list(k.values())[0]
    assert isinstance(k, LA.NotebookDirectory)
    assert len(k) == 0
