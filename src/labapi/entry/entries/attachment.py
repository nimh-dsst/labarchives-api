"""Attachment entry class."""

from __future__ import annotations

from email.message import Message
from io import BytesIO
from tempfile import TemporaryFile
from typing import TYPE_CHECKING
from typing_extensions import override

from .base import Entry
from ..attachment import Attachment

if TYPE_CHECKING:
    from ...user import User


class AttachmentEntry(Entry[Attachment]):
    def __init__(self, eid: str, caption: str, user: User):
        super().__init__(eid, user)
        self._caption = caption
        self._data = None
        self._filename = None
        self._mime_type = None

    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "Attachment"

    def get_attachment(self, use_tempfile: bool = False) -> Attachment:
        # BUG: currently the implementation means that the backing buffer can be used while a reference is maintained
        #      to it
        if self._data is None or self._data.closed:
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

                assert filename is not None

            output.seek(0)

            self._data = Attachment(output, mime_type, filename, self._caption)

        return self._data

    @property
    @override
    def content(self) -> Attachment:
        """The content of the entry."""
        return self.get_attachment()

    @content.setter
    @override
    def content(self, value: Attachment):
        # NOTE: this implicitly invalidates all previous Attachments

        self._user.api_post(
            "entries/update_attachment",
            value._backing,  # pyright: ignore[reportPrivateUsage, reportArgumentType]
            filename=value.filename,
            caption=value.caption,
            eid=self.id,
            change_description="File updated via API",
        )

        if self._data:
            self._data.close()
        self._data = None

    @property
    def caption(self) -> str:
        return self._caption
