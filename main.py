"""A client for the LabArchives API."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, MutableSequence, Sequence
from datetime import datetime
from email.message import Message

from io import BufferedRandom, BufferedReader, BytesIO
from json import dumps
from mimetypes import guess_file_type
from tempfile import TemporaryFile
from typing import (
    Any,
    Generic,
    Literal,
    Self,
    Tuple,
    TypeAlias,
    TypeVar,
    overload,
    override,
)
from typing_extensions import TYPE_CHECKING, Buffer

# TODO: refreshing data - currently the API assumes it's the only one touching the data during runtime
#       this can cause its data to get out of date, needs fixing
# TODO: optimize the hot-path of "get single item of name at node", ex. a[Index.Name:"aaa"][0]

if TYPE_CHECKING:
    from tempfile import _TemporaryFileWrapper  # pyright: ignore[reportPrivateUsage]


class Notebook(NotebookTreeNode):
    """A LabArchives notebook."""

    def __init__(self, init: NotebookInit, user: User, notebooks: Notebooks):
        super().__init__()
        self._id = init.id
        self._name = init.name
        self._is_default = init.is_default
        self._user = user
        self._notebooks = notebooks
        self._inserts_from_bottom: bool | None = None

    @property
    def id(self):
        """The ID of the notebook."""
        return self._id

    @property
    def name(self):
        """The name of the notebook."""
        return self._name

    @name.setter
    def name(self, value: str):
        self._user.api_get("notebooks/modify_notebook_info", nbid=self.id, name=value)

        self._name = value

    @property
    def inserts_from_bottom(self) -> bool:
        """Whether new entries are inserted at the bottom of the page."""
        if (
            self._inserts_from_bottom is None
        ):  # XXX we can probably get this on init, should we?
            self._inserts_from_bottom = not _extract_etree(
                self._user.api_get("notebooks/notebook_info", nbid=self.id),
                {"notebook": {"add-entry-to-page-top": to_bool}},
            )["add-entry-to-page-top"]

        return self._inserts_from_bottom

    @property
    def is_default(self):  # FIXME what is this for anyways??
        """Whether the notebook is the default notebook."""
        return self._is_default

    # get info # This is basically irrelevant
    # delete notebook?
    # metadata?
    # tree tools
    #    - ex search for specific page
    #    - etc.




class NotebookPage(NotebookEntity, _MixinTreeNodeOperations):
    """A page in a notebook."""

    def __init__(
        self,
        id: str,
        name: str,
        root: Notebook,
        parent: NotebookTreeNode | None,
        # can_read_comments: bool,
        # can_write_comments: bool,
        # can_read: bool,
        # can_write: bool,
        user: User,
    ):
        super().__init__(
            id,
            name,
            root,
            parent,
            # can_read_comments,
            # can_write_comments,
            # can_read,
            # can_write,
            user,
        )
        self._entries = None

    @property
    def entries(self) -> Entries:
        """The entries on the page."""
        if self._entries is None:
            entries: list[Entry[Any]] = []

            entries_tree = self._user.api_get(
                "tree_tools/get_entries_for_page",
                page_tree_id=self.id,
                nbid=self._root.id,
                entry_data=True,
            )
            for entry in entries_tree.iterfind(".//entry"):
                entry_data = _extract_etree(
                    entry,
                    {
                        "eid": str,
                        "part-type": str,
                        "attach-file-name": str,
                        "attach-content-type": str,
                        "entry-data": str,
                    },
                )

                part_type = entry_data["part-type"]

                assert isinstance(part_type, str)

                entries.append(
                    Entry.get_entry(
                        part_type,
                        entry_data["eid"],
                        entry_data["entry-data"],
                        self._user,
                    )
                )

            self._entries = Entries(entries, self._user, self)

        return self._entries




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

            id = _extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]
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

            id = _extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]
            entry = Entry.get_entry(entry_type, id, data, self._user)

        self._entries[id] = entry
        return entry  # pyright: ignore[reportReturnType]
        # XXX the python typechecker here does not understand that entry_type is constrained
        #     and so picks a nonsense overload which tries to return too wide of a type

    # This class exists solely so we can add entries in future / delete them


T = TypeVar("T")


class Entry(ABC, Generic[T]):
    """An entry on a page."""

    @overload
    @staticmethod
    def get_entry(part_type: Literal["heading"], *args: Any) -> HeaderEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["plain text entry"], *args: Any) -> PlainTextEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["text entry"], *args: Any) -> TextEntry:
        pass

    @overload
    @staticmethod
    def get_entry(
        part_type: Literal["attachment", "Attachment"], *args: Any
    ) -> AttachmentEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: Literal["widget entry"], *args: Any) -> WidgetEntry:
        pass

    @overload
    @staticmethod
    def get_entry(part_type: str, *args: Any) -> Entry[Any]:
        pass

    @staticmethod
    def get_entry(part_type: str, *args: Any) -> Entry[Any]:  # pyright: ignore[reportInvalidTypeVarUse]
        match part_type.lower().strip():
            case "plain text entry" | "sketch entry":
                return PlainTextEntry(*args)
            case "text entry":
                return TextEntry(*args)
            case "heading":
                return HeaderEntry(*args)
            case "attachment":
                return AttachmentEntry(*args)
            case "widget entry":
                return WidgetEntry(*args)
            case other:
                raise NotImplementedError(f"part type {other}")

    # TODO perms
    def __init__(
        self,
        eid: str,
        user: User,
    ):
        super().__init__()
        self._id = eid
        self._user = user

    @property
    def id(self):
        """The ID of the entry."""
        return self._id

    @property
    @abstractmethod
    def content_type(self) -> str:
        """The content type of the entry."""
        raise NotImplementedError

    @property
    @abstractmethod
    def content(self) -> T:
        """The content of the entry."""
        raise NotImplementedError

    @content.setter
    @abstractmethod
    def content(self, value: T) -> None:
        """Setting the content of the entry"""
        raise NotImplementedError


class BaseTextEntry(Entry[str], ABC):
    def __init__(self, eid: str, data: str, user: User):
        super().__init__(eid, user)
        self._entry_data = data

    @property
    @override
    def content(self) -> str:
        """The content of the entry."""
        return self._entry_data

    @content.setter
    @override
    def content(self, value: str) -> None:
        self._user.api_post("entries/update_entry", {"entry_data": value}, eid=self.id)

        self._entry_data = value


class TextEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "text entry"


class HeaderEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "heading"


class PlainTextEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "plain text entry"


class WidgetEntry(BaseTextEntry):
    @property
    @override
    def content_type(self):
        """The content type of the entry."""
        return "widget entry"


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

    @overload
    @staticmethod
    def from_file(file: BufferedReader) -> Attachment:
        pass

    @overload
    @staticmethod
    def from_file(file: BufferedRandom) -> Attachment:
        pass

    @staticmethod
    def from_file(file: BufferedReader | BufferedRandom) -> Attachment:
        mime_type = guess_file_type(file.name)[0] or "application/octet-stream"
        return Attachment(
            file,  # pyright: ignore[reportUnknownVariableType, reportArgumentType]
            mime_type,
            file.name,
            caption=f"API-uploaded {mime_type} file.",
        )

    def __init__(
        self,
        backing: BufferedRandom
        | BufferedReader
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


class Comment:
    """A comment on an entity."""

    pass
