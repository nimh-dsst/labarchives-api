from typing import override
from tree.mixins import ITreeContainer, HasNameMixin, AbstractBaseTreeNode
from user import User
from util.notebookinit import NotebookInit
from util.extract import extract_etree, to_bool

from tree.directory import NotebookDirectory
from tree.page import NotebookPage


class Notebook(ITreeContainer):
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

    def get_tree(self, parent: ITreeContainer):
        """Gets the tree of a notebook.

        Args:
            parent: The parent of the tree.

        Returns:
            The tree of the notebook.
        """
        xml_tree = self._user.api_get(
            "tree_tools/get_tree_level",
            nbid=self.id,
            parent_tree_id=parent.tree_id,
        )

        nodes: list[AbstractBaseTreeNode] = []

        for subtree in xml_tree.iterfind(".//level-node"):
            node = extract_etree(
                subtree,
                {
                    "is-page": to_bool,
                    "tree-id": str,
                    "display-text": str,
                    # "user-access": {
                    #     "can-read": to_bool,
                    #     "can-write": to_bool,
                    #     "can-read-comments": to_bool,
                    #     "can-write-comments": to_bool,
                    # },
                },
            )  # TODO do we want to handle errors here?

            args = (
                node["tree-id"],
                node["display-text"],
                self,
                parent,
                self.user,
            )

            if node["is-page"]:
                nodes.append(NotebookPage(*args))
            else:
                nodes.append(NotebookDirectory(*args))

        return nodes
