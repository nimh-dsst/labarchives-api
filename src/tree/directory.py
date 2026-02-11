from typing import Self, override
from tree.mixins import TreeDeleteMixin, TreeRenameMixin, ITreeContainer, ITreeCopy


class NotebookDirectory(ITreeContainer, ITreeCopy, TreeDeleteMixin, TreeRenameMixin):
    @override
    def copy_to(self, destination: ITreeContainer) -> Self:
        raise NotImplementedError

    @property
    def id(self) -> str:
        return super().id

    def _ensure_populated(self) -> None:
        raise NotImplementedError
