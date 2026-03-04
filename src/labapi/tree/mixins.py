"""Tree Mixins Module.

This module defines abstract base classes and mixins that form the hierarchical
structure of LabArchives notebooks, directories, and pages. These classes
provide common functionalities and properties for tree nodes and containers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import ItemsView, Iterator, KeysView, Mapping, MutableSequence, Sequence, ValuesView
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Self, cast, overload, override

from labapi.util import IdIndex, IdOrNameIndex, Index, NameIndex, extract_etree, to_bool

from datetime import timedelta
import time


if TYPE_CHECKING:
    from labapi.user import User

    from .directory import NotebookDirectory
    from .page import NotebookPage


class HasNameMixin:
    """A mixin class that provides a `name` attribute for tree nodes.

    Classes inheriting from this mixin are expected to have a `_name` instance
    variable.
    """

    def __init__(self, name: str):
        """Initializes the HasNameMixin with a given name.

        :param name: The name of the tree node.
        """
        super().__init__()
        self._name = name

    @property
    def name(self) -> str:
        """The name of the tree node.

        :returns: The name of the node.
        """
        return self._name


class AbstractBaseTreeNode(ABC, HasNameMixin):
    """Abstract base class for any node within the LabArchives tree structure.

    This class provides fundamental properties and methods common to all
    tree nodes, such as ID, name, references to parent and root, and the
    associated user.

    :param tree_id: The unique identifier for this node within the LabArchives tree.
    :param name: The display name of the node.
    :param root: The root node of the tree (e.g., the Notebook).
    :param parent: The parent node of this node in the tree.
    :param user: The authenticated user associated with this node.
    """

    def __init__(
        self,
        tree_id: str,
        name: str,
        root: AbstractTreeContainer,
        parent: AbstractTreeContainer,
        user: User,
    ):
        super().__init__(name)
        self._root: AbstractTreeContainer = root
        self._parent: AbstractTreeContainer = parent
        self._tree_id: str = tree_id
        self._user = user

    @property
    def root(self) -> AbstractTreeContainer:
        """The root node of the tree (e.g., the Notebook).

        :returns: The root tree container.
        """
        return self._root

    @property
    def parent(self) -> AbstractTreeContainer:
        """The parent node of this node in the tree.

        :returns: The parent tree container.
        """
        return self._parent

    @property
    def user(self) -> User:
        """The authenticated user associated with this node.

        :returns: The user object.
        """
        return self._user

    @property
    @abstractmethod
    def id(self) -> str:
        """The unique identifier of the node.

        :returns: The node's ID.
        """
        return self.tree_id

    @property
    def tree_id(self) -> str:
        """The unique identifier for this node within the LabArchives tree.

        This is often the same as `id` but can be used to distinguish if needed.

        :returns: The tree ID of the node.
        """
        return self._tree_id

    @abstractmethod
    def is_dir(self) -> bool:
        """Method to determine if the node is a directory.

        :returns: True if the node is a directory, False otherwise.
        """
        return False

    @abstractmethod
    def refresh(self) -> None:
        """Refreshes the node's data from the LabArchives API.

        This method updates the node's properties (such as name, ID, and children)
        by fetching the latest data from the server. This is useful when the
        node's state may have changed externally.
        """
        raise NotImplementedError()

    def traverse(self, path: str) -> AbstractBaseTreeNode:
        """Traverses the notebook's tree structure to find a node by its path.

        The path segments should be separated by '/'. Each segment is treated
        as a name to look up in the current container. Paths starting with '/'
        are absolute (relative to the notebook root), while paths without a
        leading '/' are relative to the current container.

        Special path segments:
        - '..' navigates to the parent container

        .. note::
           - When multiple children have the same name, this method returns the first match.
           - Empty path segments (from trailing slashes or multiple consecutive slashes)
             will attempt to look up nodes with empty string names.
           - '.' is not treated specially; it will look for a node literally named '.'.

        .. warning::
           Nodes with names that are literally '..' cannot be accessed via
           this method, as '..' is reserved for parent navigation.

        :param path: The slash-separated path to the desired node (e.g., "My Folder/My Page" or "/Folder/Subfolder/Page").
        :returns: The :class:`AbstractTreeContainer` or :class:`AbstractTreeNode` found at the specified path.
        :raises RuntimeError: If a segment in the path does not lead to a directory.
        :raises KeyError: If a node at any segment of the path is not found.
        """

        if path.startswith("/"):
            curr = self.root
        else:
            curr = self

        segments = path.lstrip("/").split("/")

        parsed_segments: list[str] = []

        for segment in segments:
            parsed_segments.append(segment)
            if segment == "..":
                curr = curr.parent
            elif isinstance(curr, AbstractTreeContainer):
                curr = curr[segment]
            else:
                raise RuntimeError(f"{'/'.join(parsed_segments)} is not a directory")

        return curr

    def as_dir(self) -> AbstractTreeContainer:
        """Casts this node to an :class:`AbstractTreeContainer` if it is a directory.

        This method provides a convenient way to perform directory-specific
        operations on a node after checking its type, with static type
        checking support.

        :returns: The node cast to an :class:`AbstractTreeContainer`.
        :raises TypeError: If the node is not a directory (i.e., `is_dir()` returns `False`).
        """
        if self.is_dir():
            return cast(AbstractTreeContainer, self)
        else:
            raise TypeError("Node is not a directory")
        
    def as_page(self) -> NotebookPage:
        """Casts this node to a :class:`NotebookPage` if it is a page.

        This method provides a convenient way to perform page-specific
        operations on a node after checking its type, with static type
        checking support.

        :returns: The node cast to a :class:`NotebookPage`.
        :raises TypeError: If the node is not a page (i.e., `is_dir()` returns `True`).
        """
        if not self.is_dir():
            from . import page

            return cast(page.NotebookPage, self)
        else:
            raise TypeError("Node is not a page")


class AbstractTreeNode(AbstractBaseTreeNode):
    """Abstract base class for a non-container node within the LabArchives tree structure.

    This class extends :class:`AbstractBaseTreeNode` with functionalities for
    modifying the node's name, copying, moving, and deleting the node.
    """

    @HasNameMixin.name.setter
    def name(self, value: str):
        """Sets the name of the tree node.

        This operation updates the node's name in LabArchives via an API call.

        :param value: The new name for the node.
        """
        self.user.api_get(
            "tree_tools/update_node",
            nbid=self.root.id,
            tree_id=self.tree_id,
            display_text=value,
        )

        self._name = value

    @abstractmethod
    def copy_to(self, destination: AbstractTreeContainer) -> Self:
        """Method to copy this node to a specified destination container.

        :param destination: The target container to copy the node to.
        :returns: A new instance of the copied node in the destination.
        """

    def move_to(self, destination: AbstractTreeContainer) -> Self:
        """Moves this node to a specified destination container.

        This operation updates the node's parent in LabArchives via an API call
        and updates the local tree structure.

        :param destination: The target container to move the node to.
        :returns: The instance of the moved node.
        """
        self._user.api_get(
            "tree_tools/update_node",
            nbid=self.root.id,
            tree_id=self.tree_id,
            parent_tree_id=destination.tree_id,
        )
        del self.parent._children[  # pyright: ignore[reportPrivateUsage]
            self.parent.children.index(self)
        ]  # This removes current node from old parent in-place
        self._parent = destination
        self.parent._children.append(self)  # pyright: ignore[reportPrivateUsage]
        # This adds current node to new parent in-place
        return self

    def delete(self) -> Self:
        """Deletes this node by moving it to a special "API Deleted Items" directory.

        If the "API Deleted Items" directory does not exist, it will be created.
        The node's name will be updated to reflect its deletion time.

        :returns: The instance of the deleted node.
        """
        # XXX: should the creation of the deleted directory be singletoned by the Client
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
    """Abstract base class for a tree node that can contain other tree nodes (e.g., Notebooks, Directories).

    This class extends :class:`AbstractBaseTreeNode` and implements `collections.abc.Mapping`
    to allow access to its children by ID or name. It provides methods for managing
    its children, such as creating new pages or directories.
    """

    def __init__(
        self,
        tree_id: str,
        name: str,
        root: AbstractTreeContainer,
        parent: AbstractTreeContainer,
        user: User,
    ):
        """Initializes an AbstractTreeContainer.

        :param tree_id: The unique identifier for this container within the LabArchives tree.
        :param name: The display name of the container.
        :param root: The root node of the tree (e.g., the Notebook).
        :param parent: The parent node of this container in the tree.
        :param user: The authenticated user associated with this container.
        """
        super().__init__(tree_id, name, root, parent, user)
        self._children: MutableSequence[AbstractTreeNode] = []
        self._populated: bool = False

    @property
    def children(self) -> Sequence[AbstractTreeNode]:
        """A sequence of the direct children nodes within this container.

        :returns: A sequence of :class:`AbstractTreeNode` objects.
        """
        self._ensure_populated()
        return self._children

    def _ensure_populated(self) -> None:
        """Ensures that the children of this container have been loaded from the API.

        If the children have not been loaded yet, it makes an API call to
        retrieve the tree level and populates the `_children` list.
        """
        from . import directory, page

        if not self._populated:
            xml_tree = self.user.api_get(
                "tree_tools/get_tree_level",
                nbid=self.root.id,
                parent_tree_id=self.tree_id,
            )

            nodes: list[AbstractTreeNode] = []

            for subtree in xml_tree.iterfind(".//level-node"):
                node = extract_etree(
                    subtree,
                    {
                        "is-page": to_bool,
                        "tree-id": str,
                        "display-text": str,
                    },
                )  # TODO do we want to handle errors here?

                args = (
                    node["tree-id"],
                    node["display-text"],
                    self.root,
                    self,
                    self._user,
                )

                if node["is-page"]:
                    nodes.append(page.NotebookPage(*args))
                else:
                    nodes.append(directory.NotebookDirectory(*args))

            self._children = nodes
            self._populated = True

    def __len__(self) -> int:
        self._ensure_populated()
        return len(self.children)

    def __iter__(self) -> Iterator[str]:
        return iter(node.name for node in self.children)

    @override
    def keys(self) -> KeysView[str]:
        """A view of the names of the children within this container.

        :returns: A keys view of child names.
        """
        self._ensure_populated()
        return KeysView({node.name: node for node in self.children})

    @override
    def items(self) -> ItemsView[str, AbstractBaseTreeNode]:
        """A view of the names and child nodes within this container.

        :returns: An items view of (name, node) pairs.
        """
        self._ensure_populated()
        return ItemsView({node.name: node for node in self.children})

    @override
    def values(self) -> ValuesView[AbstractBaseTreeNode]:
        """A view of the child nodes within this container.

        :returns: A values view of child nodes.
        """
        self._ensure_populated()
        return ValuesView({node.name: node for node in self.children})

    @overload
    def __getitem__(self, key: str) -> AbstractBaseTreeNode: ...

    @overload
    def __getitem__(self, key: IdIndex) -> AbstractBaseTreeNode: ...

    @overload
    def __getitem__(self, key: NameIndex) -> Sequence[AbstractBaseTreeNode]: ...

    def __getitem__(
        self, key: IdOrNameIndex
    ) -> AbstractBaseTreeNode | Sequence[AbstractBaseTreeNode]:
        """Allows accessing child nodes by their ID or name.

        - If `key` is a string, it attempts to find a single child with that name.
        - If `key` is a slice with start of :class:`~labapi.util.index.IdIndex` (e.g., ``Index.Id:"some_id"``),
          it returns the child with the matching ID.
        - If `key` is a slice with start of :class:`~labapi.util.index.NameIndex` (e.g., ``Index.Name:"some_name"``),
          it returns a list of all children with the matching name (as names are not unique).

        This method ensures the children are populated before attempting to access them.

        :param key: The index to use for accessing children.
        :returns: A single :class:`AbstractBaseTreeNode` or a sequence of :class:`AbstractBaseTreeNode`.
        :raises KeyError: If a single node is requested by ID or unique name and not found.
        """
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

    def enumerate_all(
        self,
        _current_depth: int = 0,
        *,
        max_depth: int = 1,
        timeout: timedelta | None = None,
        _timeout: float | None = None,
    ) -> Sequence[str]:
        """Enumerates all children (directories and pages) up to a specified depth.

        Returns relative path strings from the current container for all descendant
        nodes, including both directories and pages. Each path is relative to this
        container (e.g., "Folder/Page" or "Folder/Subfolder/Page").

        :param max_depth: The maximum depth to traverse. Default is 1 (only immediate children).
        :param timeout: The maximum time to spend enumerating children.
        :returns: A sequence of relative path strings for all descendants.
        """
        current: MutableSequence[str] = []

        if _current_depth >= max_depth:
            return current

        if timeout is None:
            timeout = timedelta(seconds=5)

        if _timeout is None:
            _timeout = time.monotonic() + timeout.total_seconds()

        for name, child in self.items():
            if time.monotonic() > _timeout:
                break

            current.append(name)

            try:
                container = child.as_dir()
                current.extend(
                    [
                        f"{name}/{child_path}"
                        for child_path in container.enumerate_all(
                            _current_depth + 1, max_depth=max_depth, _timeout=_timeout
                        )
                    ]
                )
            except TypeError:
                pass

        return current

    def enumerate_dirs(
        self, *, max_depth: int = 1, timeout: timedelta | None = None
    ) -> Sequence[str]:
        """Enumerates only directories up to a specified depth.

        Returns relative path strings from the current container for all descendant
        directories (excluding pages). Each path is relative to this container.

        :param max_depth: The maximum depth to traverse. Default is 1 (only immediate children).
        :param timeout: The maximum time to spend enumerating children.
        :returns: A sequence of relative path strings for all descendant directories.
        """
        all_names = self.enumerate_all(max_depth=max_depth, timeout=timeout)
        return [name for name in all_names if self.traverse(name).is_dir()]

    def enumerate_pages(
        self, *, max_depth: int = 1, timeout: timedelta | None = None
    ) -> Sequence[str]:
        """Enumerates only pages up to a specified depth.

        Returns relative path strings from the current container for all descendant
        pages (excluding directories). Each path is relative to this container.

        :param max_depth: The maximum depth to traverse. Default is 1 (only immediate children).
        :param timeout: The maximum time to spend enumerating children.
        :returns: A sequence of relative path strings for all descendant pages.
        """
        all_names = self.enumerate_all(max_depth=max_depth, timeout=timeout)
        return [name for name in all_names if not self.traverse(name).is_dir()]

    def create_page(self, name: str) -> NotebookPage:
        """Creates a new page within this container.

        :param name: The name of the new page.
        :returns: The newly created :class:`~labapi.tree.page.NotebookPage` object.
        :raises RuntimeError: If the API call to create the page fails.
        """
        from . import page

        # TODO take into account whether can write in this directory
        create_tree = self.user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id=self.tree_id,
            display_text=name,
            is_folder="false",
        )
        tree_id = extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_page = page.NotebookPage(tree_id, name, self, self.root, self.user)
        self._children.append(new_page)
        return new_page

    def create_directory(self, name: str) -> NotebookDirectory:
        """Creates a new directory within this container.

        :param name: The name of the new directory.
        :returns: The newly created :class:`~labapi.tree.directory.NotebookDirectory` object.
        :raises RuntimeError: If the API call to create the directory fails.
        """
        from . import directory

        # TODO take into account whether can write in this directory
        create_tree = self._user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id=self.tree_id,
            display_text=name,
            is_folder="true",
        )
        tree_id = extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_dir = directory.NotebookDirectory(tree_id, name, self, self.root, self.user)
        self._children.append(new_dir)
        return new_dir

    @override
    def is_dir(self) -> Literal[True]:
        """Indicates that this node is a directory (container).

        :returns: Always True.
        """
        return True

    @override
    def refresh(self) -> None:
        """Refreshes the container by clearing its cached children.

        This method clears the internal children cache, forcing the container
        to re-fetch its children from the LabArchives API on the next access.

        .. note::
           Currently only clears the children list. Future implementation should
           invalidate all children before clearing.
        """
        # TODO invalidate all children first
        self._children = []
        self._populated = False
