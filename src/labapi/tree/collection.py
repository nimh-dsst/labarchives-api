from __future__ import annotations
from typing import Mapping, Sequence, overload, override, Literal
from .notebook import Notebook
from ..util.index import IdOrNameIndex, Index
from ..util.notebookinit import NotebookInit
from ..util.extract import extract_etree
from ..user import User

class Notebooks(Mapping[IdOrNameIndex, Notebook | Sequence[Notebook]]):
    """A collection of notebooks."""

    def __init__(self, notebooks: Sequence[NotebookInit], user: User):
        super().__init__()
        self._user = user
        self._notebooks = [Notebook(n, user, self) for n in notebooks]
        self._notebooks_by_id = {n.id: n for n in self._notebooks}

    @overload
    def __getitem__(self, key: str) -> Notebook:
        pass

    @overload
    def __getitem__(self, key: "slice[Literal[Index.Id], str, None]") -> Notebook:
        pass

    @overload
    def __getitem__(
        self, key: "slice[Literal[Index.Name], str, None]"
    ) -> list[Notebook]:
        pass

    @override
    def __getitem__(self, key: IdOrNameIndex) -> Notebook | list[Notebook]:
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

    @override
    def __iter__(self):
        return iter([c.id for c in self._notebooks])

    @override
    def __len__(self):
        return len(self._notebooks)

    @override
    def values(self):
        return self._notebooks_by_id.values()

    def create_notebook(self, name: str) -> Notebook:
        """Creates a new notebook.

        Args:
            name: The name of the notebook.

        Returns:
            The new notebook.
        """
        nbid = extract_etree(
            self._user.api_get(
                "notebooks/create_notebook", name=name, initial_folders="Empty"
            ),
            {"nbid": str},
        )["nbid"]

        # TODO check that the notebook with same id does not already exist
        #      why though? that should never happen unless their api is broken

        new_notebook = Notebook(NotebookInit(nbid, name, False), self._user, self)

        self._notebooks.append(new_notebook)
        self._notebooks_by_id[nbid] = new_notebook

        return new_notebook