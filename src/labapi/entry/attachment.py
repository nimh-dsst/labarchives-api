"""Attachment data structure."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Buffer
from mimetypes import guess_type
from os.path import basename
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from io import BufferedRandom, BufferedReader, BytesIO
    from tempfile import (  # pyright: ignore[reportPrivateUsage]
        SpooledTemporaryFile,
    )

# NOTE: from Pylance
# Unfortunately PEP 688 does not allow us to distinguish read-only
# from writable buffers. We use these aliases for readability for now.
# Perhaps a future extension of the buffer protocol will allow us to
# distinguish these cases in the type system.
# Same as WriteableBuffer, but also includes read-only buffer types (like bytes).
ReadableBuffer: TypeAlias = Buffer  # stable


class Attachment:
    """Represents an attachment file with associated metadata.

    This class wraps a file-like object (such as BytesIO or TemporaryFile) along
    with metadata like MIME type, filename, and caption. It provides a convenient
    interface for working with file attachments in LabArchives.

    .. note::
       Write operations to the backing buffer need explicit syncing with the server.
    """

    @staticmethod
    def from_file(
        file: BufferedReader | BufferedRandom,
        filename: str | None = None,
    ) -> Attachment:
        """Creates an Attachment from a file object by cloning its content.

        The content of the provided file is copied into a temporary buffer,
        making the Attachment independent of the original file's state.
        The MIME type is automatically guessed from the local file name or the
        explicit remote filename override. If the MIME type cannot be determined,
        it defaults to "application/octet-stream".

        :param file: The file object to create an attachment from. Must have a `name` attribute.
        :param filename: Optional explicit remote filename to store in LabArchives.
            Defaults to the basename of ``file.name``.
        :returns: A new Attachment object wrapping a clone of the file.
        """
        remote_filename = filename or basename(file.name)
        mime_type = guess_type(filename or file.name)[0] or "application/octet-stream"

        # Create a spooled temporary file as the new backing buffer.
        # It stays in memory until it reaches 4MB, then rolls over to disk.
        backing = tempfile.SpooledTemporaryFile(max_size=4 * 1024 * 1024, mode="w+b")
        shutil.copyfileobj(file, backing)
        backing.seek(0)

        return Attachment(
            backing,  # pyright: ignore[reportArgumentType]
            mime_type,
            remote_filename,
            caption=f"API-uploaded {mime_type} file.",
        )

    def __init__(
        self,
        backing: BufferedRandom
        | BufferedReader
        | BytesIO
        | SpooledTemporaryFile[bytes],
        mime_type: str,
        filename: str,
        caption: str,
    ):
        """Initializes an Attachment object.

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

    def __getattr__(self, attr: str):
        """Delegates attribute access to the backing file-like object.

        This allows the Attachment to behave like the underlying file object
        for operations like read(), write(), etc.

        :param attr: The attribute name to access on the backing object.
        :returns: The attribute value from the backing object.
        :raises AttributeError: If the attribute does not exist on the backing object.
        """
        return getattr(self._backing, attr)

    @property
    def filename(self) -> str:
        """The filename of the attachment.

        :returns: The filename.
        """
        return self._filename

    @property
    def mime_type(self) -> str:
        """The MIME type of the attachment.

        :returns: The MIME type (e.g., "image/png", "application/pdf").
        """
        return self._mime_type

    @property
    def caption(self) -> str:
        """The caption associated with the attachment.

        :returns: The caption text.
        """
        return self._caption
