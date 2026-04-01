"""Notebook Collection Module.

This module defines the :class:`~labapi.tree.collection.Notebooks` class,
which acts as a collection manager for a user's LabArchives notebooks.
It provides methods for accessing, iterating over, and creating notebooks.
"""

from __future__ import annotations

from collections.abc import ItemsView, Iterator, KeysView, Mapping, Sequence, ValuesView
from typing import TYPE_CHECKING, Literal, overload, override

from labapi.exceptions import ApiError
from labapi.util import IdOrNameIndex, Index, NotebookInit, extract_etree

from .notebook import Notebook

if TYPE_CHECKING:
    from labapi.user import User


class Notebooks(Mapping[IdOrNameIndex, Notebook | Sequence[Notebook]]):
    """A collection of LabArchives notebooks accessible to a user.

    This class provides dictionary-like access to notebooks by their ID or name,
    and supports creating new notebooks. It manages a list of :class:`~labapi.tree.notebook.Notebook`
    objects.
    """

    def __init__(self, notebooks: Sequence[NotebookInit], user: User):
        """Initializes the Notebooks collection.

        :param notebooks: A sequence of :class:`~labapi.util.notebookinit.NotebookInit` objects
                          containing initial data for the notebooks.
        :param user: The authenticated :class:`~labapi.user.User` associated with these notebooks.
        """
        super().__init__()
        self._user = user
        self._notebooks = [Notebook(n, user, self) for n in notebooks]
        self._notebooks_by_id = {n.id: n for n in self._notebooks}

    @overload
    def __getitem__(self, key: str) -> Notebook: ...

    @overload
    def __getitem__(self, key: slice[Literal[Index.Id], str, None]) -> Notebook: ...

    @overload
    def __getitem__(
        self, key: slice[Literal[Index.Name], str, None]
    ) -> list[Notebook]: ...

    @override
    def __getitem__(self, key: IdOrNameIndex) -> Notebook | list[Notebook]:
        """Retrieves a notebook or a list of notebooks from the collection using various indexing methods.

        - If `key` is a string, it attempts to find a single notebook with that name.
        - If `key` is a slice with start of :class:`~labapi.util.index.IdIndex` (e.g., ``Index.Id:"some_id"``),
          it returns the notebook with the matching ID.
        - If `key` is a slice with start of :class:`~labapi.util.index.NameIndex` (e.g., ``Index.Name:"some_name"``),
          it returns a list of all notebooks with the matching name (as names are not unique).

        :param key: The index to use for accessing notebooks. Can be a string (for name lookup),
                    or a slice with :attr:`~labapi.util.index.Index.Id` or :attr:`~labapi.util.index.Index.Name`.
        :returns: A single :class:`~labapi.tree.notebook.Notebook` object or a list of them.
        :raises KeyError: If a single notebook is requested by ID or unique name and not found.
        """
        match key:
            case slice(start=Index.Id, stop=val):
                return self._notebooks_by_id[val]
            case slice(start=Index.Name, stop=val):
                return [node for node in self._notebooks if node.name == val]
            case str():
                for node in self._notebooks:
                    if node.name == key:
                        return node
                raise KeyError(f'Notebook with name "{key}" not found')
            case _:
                raise TypeError(
                    "Invalid key type. Use `str`, `Index.Id:<id>`, or `Index.Name:<name>`."
                )

    @override
    def __iter__(self) -> Iterator[str]:
        return iter([c.name for c in self._notebooks])
    
    @override
    def __reversed__(self) -> Iterator[str]:
        return reversed([c.name for c in self._notebooks])

    @override
    def __len__(self) -> int:
        return len(self._notebooks)

    @override
    def keys(self) -> KeysView[str]:
        """A mapping-compatible view of notebook names.

        :returns: A keys view of notebook names.
        """
        return KeysView({n.name: n for n in self._notebooks})

    @override
    def items(self) -> ItemsView[str, Notebook]:
        """A mapping-compatible view of ``(name, notebook)`` pairs.

        :returns: An items view of ``(name, notebook)`` pairs.
        """
        return ItemsView({n.name: n for n in self._notebooks})

    @override
    def values(self) -> ValuesView[Notebook]:
        """A mapping-compatible view of notebook objects.

        :returns: A values view of notebook objects.
        """
        return ValuesView({n.name: n for n in self._notebooks})

    def all_keys(self) -> Sequence[str]:
        """A list of notebook names in collection order, preserving duplicates."""
        return [n.name for n in self._notebooks]

    def all_items(self) -> Sequence[tuple[str, Notebook]]:
        """A list of ``(name, notebook)`` tuples in collection order, preserving duplicates."""
        return [(n.name, n) for n in self._notebooks]

    def all_values(self) -> Sequence[Notebook]:
        """A list of notebook objects in collection order, preserving duplicates."""
        return list(self._notebooks)

    def create_notebook(self, name: str) -> Notebook:
        """Creates a new notebook in LabArchives.

        :param name: The name of the new notebook.
        :returns: The newly created :class:`~labapi.tree.notebook.Notebook` object.
        :raises RuntimeError: If the API call to create the notebook fails.
        """
        nbid = extract_etree(
            self._user.api_get(
                "notebooks/create_notebook", name=name, initial_folders="Empty"
            ),
            {"nbid": str},
        )["nbid"]

        if nbid in self._notebooks_by_id:
            raise ApiError(f"API returned an existing notebook ID: {nbid}")

        new_notebook = Notebook(NotebookInit(nbid, name, False), self._user, self)

        self._notebooks.append(new_notebook)
        self._notebooks_by_id[nbid] = new_notebook

        return new_notebook
