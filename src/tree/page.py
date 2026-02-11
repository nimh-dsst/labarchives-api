from typing import Self, override
from tree.mixins import TreeDeleteMixin, TreeRenameMixin, ITreeContainer, ITreeCopy


class NotebookPage(ITreeCopy, TreeDeleteMixin, TreeRenameMixin):
    @property
    @override
    def id(self) -> str:
        return super().id

    @override
    def copy_to(self, destination: ITreeContainer) -> Self:
        raise NotImplementedError
