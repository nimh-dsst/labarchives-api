from __future__ import annotations
from typing import override
from .mixins import AbstractTreeContainer, AbstractTreeNode


class NotebookDirectory(AbstractTreeContainer, AbstractTreeNode):
    @override
    def copy_to(self, destination: AbstractTreeContainer) -> NotebookDirectory:
        new_dir = destination.create_directory(self.name)

        for child in self.children:
            child.copy_to(new_dir)

        return new_dir

    @property
    def id(self) -> str:
        return super().id
