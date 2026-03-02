from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest

import labapi as LA
from labapi.util.extract import _flatten_dict, to_bool


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
