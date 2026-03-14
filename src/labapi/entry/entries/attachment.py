"""Attachment Entry Module.

This module defines the :class:`~labapi.entry.entries.attachment.AttachmentEntry` class,
which represents an attachment entry within a LabArchives page.
"""

from __future__ import annotations

from email.message import Message
from io import BytesIO
from tempfile import TemporaryFile
from typing import TYPE_CHECKING, override

from labapi.entry.attachment import Attachment
from labapi.exceptions import ApiError

from .base import Entry

if TYPE_CHECKING:
    from labapi.user import User


class AttachmentEntry(Entry[Attachment], part_type="Attachment"):
    """Represents an attachment entry on a LabArchives page.

    This class handles the retrieval and updating of file attachments,
    providing access to the attachment's content, filename, and caption.
    """

    def __init__(self, eid: str, caption: str, user: User):
        """Initializes an AttachmentEntry object.

        :param eid: The unique ID of the entry.
        :param caption: The caption associated with the attachment.
        :param user: The authenticated user.
        """
        super().__init__(eid, caption, user)
        self._filedata = None
        self._filename = None
        self._mime_type = None

    def get_attachment(self, use_tempfile: bool = False) -> Attachment:
        """Retrieves the attachment data.

        The attachment data is fetched from the LabArchives API and cached.
        Subsequent calls will return the cached data.

        :param use_tempfile: If True, the attachment data will be stored in a
                             temporary file; otherwise, in an in-memory BytesIO object.
                             Defaults to False.
        :returns: An :class:`~labapi.entry.attachment.Attachment` object containing the file data and metadata.
        """
        # BUG: currently the implementation means that the backing buffer can be used while a reference is maintained
        #      to it
        # TODO: we should probably return a new temporary copy every time it's asked for, tbh?
        if self._filedata is None or self._filedata.closed:
            attachment = self._user.client.stream_api_get(
                "entries/entry_attachment", uid=self._user.id, eid=self.id
            )

            if use_tempfile:
                output = TemporaryFile()
            else:
                output = BytesIO()

            try:
                while True:
                    output.write(next(attachment))
            except StopIteration as stopit:
                response = stopit.value

                msg = Message()
                msg["Content-Type"] = (
                    response.headers.get("Content-Type") or "application/octet-stream"
                )
                msg["Content-Disposition"] = response.headers.get("Content-Disposition")
                filename = msg.get_filename()
                mime_type = msg.get_content_type()

                if filename is None:
                    raise ApiError(
                        "Could not determine filename from API response headers"
                    )

            output.seek(0)

            self._filedata = Attachment(output, mime_type, filename, self._data)

        return self._filedata

    @property
    @override
    def content(self) -> Attachment:
        """The attachment content as an :class:`~labapi.entry.attachment.Attachment` object.

        This property retrieves the attachment data, caching it for subsequent access.

        :returns: The attachment object.
        """
        return self.get_attachment()

    @content.setter
    @override
    def content(self, value: Attachment):
        """Sets the attachment content.

        This operation updates the attachment in LabArchives via an API call
        and invalidates any previously cached attachment data.

        :param value: The new attachment object to upload.
        """
        # NOTE: this implicitly invalidates all previous Attachments
        # NOTE: if every time content is called we give a new copy anyways that's fine
        #       (see get_attachment())

        self._user.api_post(
            "entries/update_attachment",
            value._backing,  # pyright: ignore[reportPrivateUsage, reportArgumentType]
            filename=value.filename,
            caption=value.caption,
            eid=self.id,
            change_description="File updated via API",
        )

        self._data = value.caption

        if self._filedata:
            self._filedata.close()
        self._filedata = None

    @property
    def caption(self) -> str:
        """The caption associated with the attachment.

        :returns: The caption string.
        """
        return self._data
