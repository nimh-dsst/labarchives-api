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
    """Represents an attachment file with associated metadata.

    This class wraps a file-like object (such as BytesIO or TemporaryFile) along
    with metadata like MIME type, filename, and caption. It provides a convenient
    interface for working with file attachments in LabArchives.

    .. note::
       Write operations to the backing buffer need explicit syncing with the server.
    """

    # TODO writes need explicit syncing with server
    # NOTE or we just disable them that probly works

    # @overload
    @staticmethod
    def from_file(file: BufferedRandom) -> Attachment:
        """Creates an Attachment from a file object.

        The MIME type is automatically guessed from the file's name.
        If the MIME type cannot be determined, it defaults to "application/octet-stream".

        :param file: The file object to create an attachment from. Must have a `name` attribute.
        :returns: A new Attachment object wrapping the file.
        """
        # TODO rewrite this to clone the bufferedrandom into
        #   a tempfile or memory buffer and use that as a backing
        #   then we can use a BufferedReader as well

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
        """Initializes an Attachment object.

        :param backing: The file-like object that contains the attachment data.
                        Can be a BufferedRandom, BytesIO, or TemporaryFile.
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

        .. note::
           This passthrough mechanism may not work perfectly due to BufferedIOBase
           defining implementations of abstract functions. Consider using a Protocol
           for better type safety.

        :param attr: The attribute name to access on the backing object.
        :returns: The attribute value from the backing object.
        :raises AttributeError: If the attribute does not exist on the backing object.
        """
        # FIXME This doesn't work to passthrough stuff for some reason
        # NOTE: I expect this is because BufferedIOBase defines implementations of its
        # abstract functions :(
        # maybe we can comply with a Protocol?
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
