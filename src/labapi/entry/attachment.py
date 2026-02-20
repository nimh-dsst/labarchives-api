"""Attachment data structure."""

from __future__ import annotations

from collections.abc import Buffer
from mimetypes import guess_type
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from io import BufferedRandom, BytesIO
    from tempfile import _TemporaryFileWrapper  # pyright: ignore[reportPrivateUsage]

# NOTE: from Pylance
# Unfortunately PEP 688 does not allow us to distinguish read-only
# from writable buffers. We use these aliases for readability for now.
# Perhaps a future extension of the buffer protocol will allow us to
# distinguish these cases in the type system.
# Same as WriteableBuffer, but also includes read-only buffer types (like bytes).
ReadableBuffer: TypeAlias = Buffer  # stable


class Attachment:
    # TODO writes need explicit syncing with server
    # NOTE or we just disable them that probly works

    # @overload
    # @staticmethod
    # def from_file(file: BufferedReader) -> Attachment:
    #     pass

    # @overload
    @staticmethod
    def from_file(file: BufferedRandom) -> Attachment:
        # pass

        # @staticmethod
        # def from_file(file: BufferedReader | BufferedRandom) -> Attachment:
        mime_type = guess_type(file.name)[0] or "application/octet-stream"
        return Attachment(
            file,  # pyright: ignore[reportUnknownVariableType, reportArgumentType]
            mime_type,
            file.name,
            caption=f"API-uploaded {mime_type} file.",
        )

    def __init__(
        self,
        backing: BufferedRandom
        # | BufferedReader
        | BytesIO
        | _TemporaryFileWrapper[bytes],
        mime_type: str,
        filename: str,
        caption: str,
    ):
        self._backing = backing
        if self._backing.seekable():
            self._backing.seek(0)

        self._mime_type = mime_type
        self._filename = filename
        self._caption = caption

    def __getattr__(self, attr: str):
        # FIXME This doesn't work to passthrough stuff for some reason
        # NOTE: I expect this is because BufferedIOBase defines implementations of its
        # abstract functions :(
        return getattr(self._backing, attr)

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def mime_type(self) -> str:
        return self._mime_type

    @property
    def caption(self) -> str:
        return self._caption
