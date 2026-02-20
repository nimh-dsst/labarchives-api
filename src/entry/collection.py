"""Entries collection class."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from io import BytesIO
from json import dumps
from typing import Any, Literal, Tuple, overload, override
from typing_extensions import TYPE_CHECKING

from src.util.extract import extract_etree
from src.entry.attachment import Attachment
from src.entry.entries import Entry, HeaderEntry, TextEntry, PlainTextEntry, AttachmentEntry

if TYPE_CHECKING:
    from src.user import User
    from src.entry.json_data import JsonData
    from src.tree.page import NotebookPage


class Entries(Mapping[str, "Entry[Any]"]):
    """A collection of entries."""

    def __init__(self, entries: Sequence[Entry[Any]], user: User, page: NotebookPage):
        super().__init__()
        self._user = user
        self._page = page
        self._entries = {entry.id: entry for entry in entries}

    @override
    def __getitem__(self, key: str):
        return self._entries[key]

    @override
    def __iter__(self):
        return iter(self._entries)

    @override
    def __len__(self):
        return len(self._entries)

    @override
    def values(self):
        return self._entries.values()

    @override
    def items(self):
        return self._entries.items()

    @override
    def keys(self):
        return self._entries.keys()

    # TODO delete entries

    def create_json_entry(self, data: JsonData) -> Tuple[AttachmentEntry, TextEntry]:
        name = f"uploaded_data_{datetime.now().timestamp():.0f}.json"

        file_entry = self.create_entry(
            "Attachment",
            Attachment(
                BytesIO(dumps(data).encode()),
                "application/json",
                name,
                "Uploaded JSON file",
            ),
        )

        text_entry = self.create_entry(
            "text entry",
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
    def create_entry(self, entry_type: Literal["heading"], data: str) -> HeaderEntry:
        pass

    @overload
    def create_entry(self, entry_type: Literal["text entry"], data: str) -> TextEntry:
        pass

    @overload
    def create_entry(
        self, entry_type: Literal["plain text entry"], data: str
    ) -> PlainTextEntry:
        pass

    @overload
    def create_entry(
        self,
        entry_type: Literal["attachment", "Attachment"],
        data: Attachment,
    ) -> AttachmentEntry:
        pass

    def create_entry(
        self,
        entry_type: Literal[
            "heading", "text entry", "plain text entry", "attachment", "Attachment"
        ],
        data: str | Attachment,
    ) -> HeaderEntry | TextEntry | PlainTextEntry | AttachmentEntry:
        if entry_type == "Attachment" or entry_type == "attachment":
            assert isinstance(data, Attachment)
            entry_tree = self._user.api_post(
                "entries/add_attachment",
                data._backing,  # pyright: ignore[reportPrivateUsage, reportArgumentType]
                filename=data.filename,
                caption=data.caption,
                nbid=self._page.root.id,
                pid=self._page.id,
                change_description="File uploaded via API",
            )

            id = extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]
            entry = Entry.get_entry("attachment", id, data.caption, self._user)

        else:
            assert isinstance(data, str)
            entry_tree = self._user.api_post(
                "entries/add_entry",
                {"entry_data": data},
                part_type=entry_type,
                pid=self._page.id,
                nbid=self._page.root.id,
            )

            id = extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]
            entry = Entry.get_entry(entry_type, id, data, self._user)

        self._entries[id] = entry
        return entry  # pyright: ignore[reportReturnType]
        # XXX the python typechecker here does not understand that entry_type is constrained
        #     and so picks a nonsense overload which tries to return too wide of a type