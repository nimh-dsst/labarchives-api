from __future__ import annotations
from typing import override
from tree.mixins import AbstractTreeContainer, HasNameMixin
from user import User
from util.notebookinit import NotebookInit
from util.extract import extract_etree, to_bool
from typing_extensions import TYPE_CHECKING

if TYPE_CHECKING:
    from src.tree.collection import Notebooks


class Notebook(AbstractTreeContainer):
    def __init__(self, init: NotebookInit, user: User, notebooks: Notebooks):
        super().__init__("0", init.name, self, self, user)
        self._id = init.id
        self._is_default = init.is_default
        self._notebooks = notebooks
        self._inserts_from_bottom: bool | None = None

    @property
    @override
    def id(self) -> str:
        return self._id

    @HasNameMixin.name.setter
    def name(self, value: str):
        self.user.api_get("notebooks/modify_notebook_info", nbid=self.id, name=value)

        self._name = value

    @property
    def is_default(self):
        return self._is_default

    @property
    def inserts_from_bottom(self) -> bool:
        """Whether new entries are inserted at the bottom of the page."""
        if (
            self._inserts_from_bottom is None
        ):  # XXX we can probably get this on init, should we?
            self._inserts_from_bottom = not extract_etree(
                self._user.api_get("notebooks/notebook_info", nbid=self.id),
                {"notebook": {"add-entry-to-page-top": to_bool}},
            )["add-entry-to-page-top"]

        return self._inserts_from_bottom
