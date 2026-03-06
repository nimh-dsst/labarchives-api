"""Path utilities for navigating and creating LabArchives tree nodes."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Iterator, overload, override

if TYPE_CHECKING:
    from labapi.tree.mixins import AbstractBaseTreeNode


class NotebookPath(Sequence[str]):
    def __init__(
        self,
        part: NotebookPath | AbstractBaseTreeNode | None = None,
        *parts: str,
        parent: NotebookPath | AbstractBaseTreeNode | None = None,
    ):
        if parent is not None:
            self._parent = NotebookPath(parent)
            if not self._parent.is_absolute():
                raise ValueError("parent path must be absolute")
        else:
            self._parent = None

        if part is None:
            self._absolute = (
                NotebookPath._is_absolute_seq(parts) and self._parent is None
            )
            self._parts = NotebookPath._combine(parts, [], self._absolute)
        elif isinstance(part, NotebookPath):
            self._parts: Sequence[str] = NotebookPath._combine(
                part._parts, parts, part._absolute
            )
            self._absolute: bool = part._absolute
            self._parent = part._parent
        else:
            self._parts: Sequence[str] = NotebookPath._combine(
                NotebookPath._of_node(part), parts, True
            )
            self._absolute = True

    def __truediv__(self, other: str | NotebookPath) -> NotebookPath:
        if isinstance(other, str):
            return NotebookPath(self, other)
        return other.resolve(self)

    def to_string(self):
        if self._absolute:
            return f"/{'/'.join(self._parts)}"
        else:
            return "/".join(self._parts)

    def is_absolute(self) -> bool:
        return self._absolute

    def resolve(
        self, parent: NotebookPath | None = None, recurse: bool = False
    ) -> NotebookPath:
        if self.is_absolute():
            return self
        elif self._parent is None:
            if parent is not None:
                return NotebookPath(
                    parent.resolve() if recurse else parent, *self._parts
                )
            else:
                raise ValueError(
                    "relative path cannot be resolved without an absolute parent"
                )
        else:
            return NotebookPath(self._parent, *self._parts)

    def startswith(self, other: NotebookPath) -> bool:
        # NOTE does not resolve paths
        if len(self) < len(other):
            return False
        return self[: len(other)] == other[: len(other)]

    def is_relative_to(self, other: NotebookPath | AbstractBaseTreeNode) -> bool:
        if not isinstance(other, NotebookPath):
            other = NotebookPath(other)

        if not other._absolute and other._parent is None:
            if not self._absolute and self._parent is None:
                return self.startswith(other)
            return False

        if not self._absolute and self._parent is None:
            return True

        return self.resolve().startswith(other.resolve())

    def relative_to(self, other: NotebookPath | AbstractBaseTreeNode) -> NotebookPath:
        # # TODO walk_up param

        if not isinstance(other, NotebookPath):
            other = NotebookPath(other)

        if not self.is_relative_to(other):
            raise ValueError(f'Path "{self}" is outside of "{other}"')

        if not other._absolute and other._parent is None:
            return NotebookPath(None, *self[len(other) :])

        p_origin = other.resolve()
        p_endpoint = self.resolve(other)

        return NotebookPath(None, *p_endpoint[len(p_origin) :], parent=p_origin)

    @property
    def name(self) -> str:
        if len(self._parts):
            return self._parts[-1]
        return "."

    @property
    def parts(self) -> Sequence[str]:
        return self._parts[:-1]

    @property
    def parent(self) -> NotebookPath:
        return self.resolve() / ".."

    @override
    def __iter__(self) -> Iterator[str]:
        return iter(self._parts)

    @override
    def __len__(self) -> int:
        return len(self._parts)

    @overload
    def __getitem__(self, idx: int) -> str: ...

    @overload
    def __getitem__(self, idx: slice) -> Sequence[str]: ...

    @override
    def __getitem__(self, idx: int | slice) -> str | Sequence[str]:
        return self._parts[idx]

    @override
    def __hash__(self) -> int:
        return hash((self._absolute, tuple(self._parts)))

    @override
    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, NotebookPath):
            return False
        return (
            self._absolute == other._absolute
            and self._parts == other._parts
            and self._parent == other._parent
        )

    @override
    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.to_string()!r})"

    @override
    def __str__(self):
        return self.to_string()

    @staticmethod
    def _is_absolute_seq(a: Sequence[str]) -> bool:
        return len(a) > 0 and a[0].startswith("/")

    @staticmethod
    def _combine(a: Sequence[str], b: Sequence[str], from_root: bool) -> Sequence[str]:
        canonical: list[str] = []

        # NOTE no support for escapes
        for segment in [k.strip() for part in [*a, *b] for k in part.split("/")]:
            match segment:
                case "." | "":
                    continue
                case "..":
                    if len(canonical) == 0:
                        if not from_root:
                            canonical.append("..")
                    elif canonical[-1] == "..":
                        canonical.append("..")
                    else:
                        canonical.pop()
                case _:
                    canonical.append(segment)
        return canonical

    @staticmethod
    def _of_node(a: AbstractBaseTreeNode) -> Sequence[str]:
        stack: list[str] = []

        curr = a

        while curr is not curr.root:
            stack.append(curr.name)
            curr = curr.parent

        return stack[::-1]
