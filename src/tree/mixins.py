from typing import Self, MutableSequence, Mapping, Sequence, Iterator, overload
from abc import ABC, abstractmethod
from util.index import Index, IdOrNameIndex, IdIndex, NameIndex
from util.extract import extract_etree, to_bool
import tree.page
import tree.directory
from datetime import datetime

from typing_extensions import TYPE_CHECKING

if TYPE_CHECKING:
    from tree.directory import NotebookDirectory
    from tree.page import NotebookPage
    from user import User


class HasNameMixin:
    def __init__(self, name: str):
        super().__init__()
        self._name = name

    @property
    def name(self):
        return self._name


class AbstractBaseTreeNode(ABC, HasNameMixin):
    def __init__(
        self,
        tree_id: str,
        name: str,
        root: "AbstractTreeContainer",
        parent: "AbstractTreeContainer",
        user: User,
    ):
        super().__init__(name)
        self._root: AbstractTreeContainer = root
        self._parent: AbstractTreeContainer = parent
        self._tree_id: str = tree_id
        self._user = user

    @property
    def root(self):
        return self._root

    @property
    def parent(self):
        return self._parent

    @property
    def user(self):
        return self._user

    @property
    @abstractmethod
    def id(self) -> str:
        return self.tree_id

    @property
    def tree_id(self):
        return self._tree_id
    
class AbstractTreeNode(AbstractBaseTreeNode):
    @HasNameMixin.name.setter
    def name(self, value: str):
        self.user.api_get(
            "tree_tools/update_node",
            nbid=self.root.id,
            tree_id=self.tree_id,
            display_text=value,
        )

        self._name = value

    @abstractmethod
    def copy_to(self, destination: AbstractTreeContainer) -> Self:
        pass

    def move_to(self, destination: AbstractTreeContainer) -> Self:
        self._user.api_get(
            "tree_tools/update_node",
            nbid=self.root.id,
            tree_id=self.tree_id,
            parent_tree_id=destination.tree_id,
        )
        del self.parent.children[
            self.parent.children.index(self)
        ]  # This removes current node from old parent in-place
        self._parent = destination
        self.parent.children.append(self)  
        # This adds current node to new parent in-place
        return self
    
    def delete(self) -> Self:
        # TODO: should the creation of the deleted directory be singletoned by the Client
        # on its instantiation into a Notebook?
        api_deleted_items = self.root[Index.Name : "API Deleted Items"]

        if len(api_deleted_items) == 0:
            api_deleted_items = self.root.create_directory("API Deleted Items")
        else:
            api_deleted_items = api_deleted_items[0]
            assert isinstance(api_deleted_items, AbstractTreeContainer)

        self.name = (
            f"{self.name} - Deleted at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.move_to(api_deleted_items)

        return self

class AbstractTreeContainer(
    AbstractBaseTreeNode,
    Mapping[IdOrNameIndex, AbstractBaseTreeNode | Sequence[AbstractBaseTreeNode]],
):
    def __init__(
        self,
        tree_id: str,
        name: str,
        root: "AbstractTreeContainer",
        parent: "AbstractTreeContainer",
        user: User,
    ):
        super().__init__(tree_id, name, root, parent, user)
        self._children: MutableSequence[AbstractTreeNode] = []

    @property
    def children(self):
        return self._children

    def _ensure_populated(self) -> None:
        if len(self.children) == 0:
            xml_tree = self.user.api_get(
                "tree_tools/get_tree_level",
                nbid=self.root.id,
                parent_tree_id=self.parent.tree_id,
            )

            nodes: list[AbstractTreeNode] = []

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
                    self.root,
                    self,
                    # node["can-read-comments"],
                    # node["can-write-comments"],
                    # node["can-read"],
                    # node["can-write"],
                    self._user,
                )

                if node["is-page"]:
                    nodes.append(tree.page.NotebookPage(*args))
                else:
                    nodes.append(tree.directory.NotebookDirectory(*args))

            self._children = nodes

    def __len__(self) -> int:
        self._ensure_populated()
        return len(self.children)

    def __iter__(self) -> Iterator[str]:
        return iter(node.name for node in self.children)

    @overload
    def __getitem__(self, key: str) -> AbstractBaseTreeNode:
        pass

    @overload
    def __getitem__(self, key: IdIndex) -> AbstractBaseTreeNode:
        pass

    @overload
    def __getitem__(self, key: NameIndex) -> Sequence[AbstractBaseTreeNode]:
        pass

    def __getitem__(
        self, key: IdOrNameIndex
    ) -> AbstractBaseTreeNode | Sequence[AbstractBaseTreeNode]:
        self._ensure_populated()

        match key:
            case slice(start=Index.Id, stop=val):
                for node in self.children:
                    if node.id == val:
                        return node
                raise KeyError(f'Node with id "{val}" not found')
            case slice(start=Index.Name, stop=val):
                return [node for node in self.children if node.name == val]
            case str():
                for node in self.children:
                    if node.name == key:
                        return node
                raise KeyError(f'Node with name "{key}" not found')
            
    # TODO 
    # FIXME
    # need an indexing by relative url thing

    def create_page(self, name: str) -> NotebookPage:
        # TODO take into account whether can write in this directory
        create_tree = self.user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id=self.tree_id,
            display_text=name,
            is_folder="false",
        )
        tree_id = extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_page = tree.page.NotebookPage(tree_id, name, self, self.root, self.user)
        self._children.append(new_page)
        return new_page

    def create_directory(self, name: str) -> NotebookDirectory:
        # TODO take into account whether can write in this directory
        create_tree = self._user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id=self.tree_id,
            display_text=name,
            is_folder="true",
        )
        tree_id = extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_dir = tree.directory.NotebookDirectory(
            tree_id, name, self, self.root, self.user
        )
        self._children.append(new_dir)
        return new_dir

