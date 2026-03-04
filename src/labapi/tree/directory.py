"""Notebook Directory Module.

This module defines the :class:`~labapi.tree.directory.NotebookDirectory` class,
representing a directory (folder) within a LabArchives notebook. It extends
both :class:`~labapi.tree.mixins.AbstractTreeContainer` and
:class:`~labapi.tree.mixins.AbstractTreeNode` to allow it to contain other
nodes and be managed as a node itself.
"""

from __future__ import annotations

from typing import override

from .mixins import AbstractTreeContainer, AbstractTreeNode


class NotebookDirectory(AbstractTreeContainer, AbstractTreeNode):
    """Represents a directory (folder) within a LabArchives notebook.

    A `NotebookDirectory` can contain other directories and pages, forming
    a hierarchical structure. It inherits functionalities for both being a
    container and being a movable/modifiable node within the tree.
    """

    @override
    def copy_to(self, destination: AbstractTreeContainer) -> NotebookDirectory:
        """Copies this directory and its contents to a specified destination container.

        This operation recursively copies all child directories and pages.

        :param destination: The target container to copy the directory to.
        :returns: A new instance of the copied directory in the destination.
        """
        new_dir = destination.create_directory(self.name)

        for child in self.children:
            child.copy_to(new_dir)

        return new_dir

    @property
    @override
    def id(self) -> str:
        """The unique ID of the directory.

        :returns: The directory's ID.
        """
        return super().id

    @override
    def is_dir(self) -> bool:
        """Indicates that this node is a directory.

        :returns: Always True.
        """
        return True
