"""Attachment data structure."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Buffer
from contextlib import ExitStack
from mimetypes import guess_type
from pathlib import Path
from typing import IO, Any, BinaryIO, Protocol, cast

# NOTE: from Pylance
# Unfortunately PEP 688 does not allow us to distinguish read-only
# from writable buffers. We use these aliases for readability for now.
# Perhaps a future extension of the buffer protocol will allow us to
# distinguish these cases in the type system.
# Same as WriteableBuffer, but also includes read-only buffer types (like bytes).
type ReadableBuffer = Buffer  # stable


class NamedBinaryIO(Protocol):
    """Binary file-like object with a ``name`` attribute."""

    @property
    def name(self) -> str:
        """Return the local filename for this stream."""
        ...

    def read(self, size: int = -1, /) -> bytes:
        """Read bytes from the stream."""
        ...

    def write(self, data: ReadableBuffer, /) -> int:
        """Write bytes to the stream."""
        ...

    def seek(self, offset: int, whence: int = 0, /) -> int:
        """Move the stream cursor."""
        ...

    def tell(self) -> int:
        """Return the current stream cursor position."""
        ...

    def close(self) -> None:
        """Close the stream."""
        ...

    def seekable(self) -> bool:
        """Return whether the stream supports random access."""
        ...


class Attachment:
    """Represents an attachment file with associated metadata.

    This class wraps a file-like object (such as BytesIO or TemporaryFile) along
    with metadata like MIME type, filename, and caption. It provides a convenient
    interface for working with file attachments in LabArchives.

    .. note::
       Write operations to the backing buffer need explicit syncing with the server.
    """

    @staticmethod
    def from_file(file: NamedBinaryIO) -> Attachment:
        """Create an attachment by cloning a seekable file object.

        The content of the provided file is copied into a temporary buffer,
        making the Attachment independent of the original file's state.
        The MIME type is automatically guessed from the local file name.
        If the MIME type cannot be determined, it defaults to
        "application/octet-stream".

        :param file: The file object to create an attachment from. Must have a `name` attribute.
        :returns: A new Attachment object wrapping a clone of the file.
        """
        if not file.seekable():
            raise ValueError("Attachment.from_file requires a seekable file object")

        remote_filename = Path(file.name).name
        mime_type = guess_type(file.name)[0] or "application/octet-stream"
        original_position = file.tell()

        # Create a spooled temporary file as the new backing buffer.
        # It stays in memory until it reaches 4MB, then rolls over to disk.
        with ExitStack() as stack:
            backing = cast(
                BinaryIO,
                stack.enter_context(
                    tempfile.SpooledTemporaryFile(max_size=4 * 1024 * 1024, mode="w+b")
                ),
            )
            try:
                file.seek(0)
                shutil.copyfileobj(file, backing)
            finally:
                file.seek(original_position)
            backing.seek(0)
            stack.pop_all()

        return Attachment(
            backing,
            mime_type,
            remote_filename,
            caption=f"API-uploaded {mime_type} file.",
        )

    def __init__(
        self,
        backing: IO[bytes],
        mime_type: str,
        filename: str,
        caption: str,
    ):
        """Initialize an attachment wrapper.

        :param backing: The file-like object that contains the attachment data.
                        Can be a BufferedRandom, BufferedReader, BytesIO, or TemporaryFile.
        :param mime_type: The MIME type of the attachment (e.g., "image/png", "application/pdf").
        :param filename: The filename of the attachment.
        :param caption: A descriptive caption for the attachment.
        """
        self._backing = backing
        if self._backing.seekable():
            self._backing.seek(0)

        self._mime_type = mime_type
        self._filename = filename
        self._caption = caption

    def __getattr__(self, attr: str) -> Any:
        """Delegate unknown attributes to the backing file object.

        This allows the Attachment to behave like the underlying file object
        for operations like read(), write(), etc.

        :param attr: The attribute name to access on the backing object.
        :returns: The attribute value from the backing object.
        :raises AttributeError: If the attribute does not exist on the backing object.
        """
        return getattr(self._backing, attr)

    def read(self, size: int = -1, /) -> bytes:
        """Read bytes from the backing attachment stream."""
        return self._backing.read(size)

    def write(self, data: ReadableBuffer, /) -> int:
        """Write bytes to the backing attachment stream."""
        return self._backing.write(data)

    def seek(self, offset: int, whence: int = 0, /) -> int:
        """Move the backing stream cursor."""
        return self._backing.seek(offset, whence)

    def tell(self) -> int:
        """Return the current backing stream cursor position."""
        return self._backing.tell()

    def close(self) -> None:
        """Close the backing attachment stream."""
        self._backing.close()

    def seekable(self) -> bool:
        """Return whether the backing stream supports random access."""
        return self._backing.seekable()

    @property
    def filename(self) -> str:
        """Return the attachment filename.

        :returns: The filename.
        """
        return self._filename

    @property
    def mime_type(self) -> str:
        """Return the attachment MIME type.

        :returns: The MIME type (e.g., "image/png", "application/pdf").
        """
        return self._mime_type

    @property
    def caption(self) -> str:
        """Return the attachment caption.

        :returns: The caption text.
        """
        return self._caption
