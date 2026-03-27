"""Entries collection class."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from io import BytesIO
from json import dumps
from typing import TYPE_CHECKING, Any, Type, TypeVar, overload, override

from labapi.util import extract_etree

from .attachment import Attachment
from .entries import AttachmentEntry, Entry, TextEntry

E = TypeVar("E", bound="Entry[Any]")

if TYPE_CHECKING:
    from labapi.tree import NotebookPage
    from labapi.user import User
    from labapi.util import JsonData


class Entries(Sequence["Entry[Any]"]):
    """A collection of entries on a LabArchives page.

    This class provides a sequence-like interface for managing entries within
    a page, including methods for creating new entries of various types.
    """

    def __init__(self, entries: Sequence[Entry[Any]], user: User, page: NotebookPage):
        """Initializes an Entries collection.

        :param entries: A sequence of :class:`~labapi.entry.Entry` objects.
        :param user: The authenticated user.
        :param page: The page that this collection belongs to.
        """
        super().__init__()
        self._user = user
        self._page = page
        self._entries: list[Entry[Any]] = list(entries)

    @overload
    def __getitem__(self, index: int) -> Entry[Any]:
        pass

    @overload
    def __getitem__(self, index: slice) -> Sequence[Entry[Any]]:
        pass

    @override
    def __getitem__(self, index: int | slice) -> Entry[Any] | Sequence[Entry[Any]]:
        return self._entries[index]

    @override
    def __iter__(self):
        return iter(self._entries)

    @override
    def __len__(self):
        return len(self._entries)

    def get_by_id(self, eid: str) -> Entry[Any]:
        """Return the entry with the given ID or raise ``KeyError``."""
        for entry in self._entries:
            if entry.id == eid:
                return entry
        raise KeyError(f"Entry with id '{eid}' not found")

    def of_type(self, cls: Type[E]) -> list[E]:
        """Return all entries that are instances of the requested class."""
        return [entry for entry in self._entries if isinstance(entry, cls)]

    def attachments(self) -> list[AttachmentEntry]:
        """Return all attachment entries."""
        return self.of_type(AttachmentEntry)

    def texts(self) -> list[TextEntry]:
        """Return all rich text entries."""
        return self.of_type(TextEntry)

    # TODO delete entries

    def create_json_entry(self, data: JsonData) -> tuple[AttachmentEntry, TextEntry]:
        """Creates a JSON data entry consisting of an attachment and a reference text entry.

        This method uploads JSON data as an attachment file and creates a
        companion text entry that references the attachment and displays
        a formatted preview of the JSON data.

        :param data: The JSON-serializable data to upload.
        :returns: A tuple containing the attachment entry and the text entry.
        """
        # TODO treat this as one entry in the code

        name = f"uploaded_data_{datetime.now().timestamp():.0f}.json"

        file_entry = self.create(
            AttachmentEntry,
            Attachment(
                BytesIO(dumps(data).encode()),
                "application/json",
                name,
                "Uploaded JSON file",
            ),
        )

        text_entry = self.create(
            TextEntry,
            f"""
<p>Reference Attachment: {name}</p>
<p>Entry ID: {file_entry.id}</p>
<pre>
{dumps(data, indent=4)}
</pre>
""",
        )
        return file_entry, text_entry

    @overload
    def create(
        self,
        cls: Type[AttachmentEntry],
        data: Attachment,
        *,
        client_ip: str | None = None,
    ) -> AttachmentEntry: ...

    @overload
    def create(self, cls: Type[E], data: str, *, client_ip: str | None = None) -> E: ...

    def create(
        self, cls: Type[E], data: str | Attachment, *, client_ip: str | None = None
    ) -> E:
        """Creates a new entry on the page.

        This method supports creating any entry type by passing the entry class directly,
        similar to :meth:`~labapi.tree.mixins.AbstractTreeContainer.create`. The created
        entry is automatically added to the collection.

        :param cls: The entry class to create (e.g., :class:`~labapi.entry.entries.TextEntry`,
                   :class:`~labapi.entry.entries.HeaderEntry`,
                   :class:`~labapi.entry.entries.AttachmentEntry`).
        :param data: The content of the entry. For text-based entries, this should be a string.
                    For :class:`~labapi.entry.entries.AttachmentEntry`, this should be an
                    :class:`~labapi.entry.Attachment` object.
        :param client_ip: Optional end-user IP to pass through on attachment uploads.
        :returns: The newly created entry object of the specified type.
        :raises RuntimeError: If the API call to create the entry fails.
        """
        if issubclass(cls, AttachmentEntry):
            assert isinstance(data, Attachment)
            upload_kwargs = {
                "filename": data.filename,
                "caption": data.caption,
                "nbid": self._page.root.id,
                "pid": self._page.id,
                "change_description": "File uploaded via API",
            }
            if client_ip is not None:
                upload_kwargs["client_ip"] = client_ip
            entry_tree = self._user.api_post(
                "entries/add_attachment",
                data._backing,  # pyright: ignore[reportPrivateUsage, reportArgumentType]
                **upload_kwargs,
            )

            eid = extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]
            entry = cls(eid, data.caption, self._user)

        else:
            assert isinstance(data, str)
            entry_tree = self._user.api_post(
                "entries/add_entry",
                {"entry_data": data},
                part_type=cls._part_type,  # pyright: ignore[reportPrivateUsage]
                pid=self._page.id,
                nbid=self._page.root.id,
            )

            eid = extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]
            entry = cls(eid, data, self._user)

        self._entries.append(entry)
        return entry
