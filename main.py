"""A client for the LabArchives API."""

from __future__ import annotations

import platform
import webbrowser
from abc import ABC, abstractmethod
from base64 import b64encode
from collections.abc import Callable, Mapping, MutableSequence, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from http.server import SimpleHTTPRequestHandler
from io import BufferedIOBase
from operator import itemgetter
from socketserver import TCPServer
from typing import Any, Generic, Literal, TypeVar, overload, override
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from warnings import deprecated

import selenium.webdriver as webdriver
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from lxml import etree
from requests import codes as status_codes
from requests import get, post

if platform.system() == "Windows":
    from winreg import HKEY_CURRENT_USER, OpenKey, QueryValueEx

    with OpenKey(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
    ) as key:
        raw_browser = QueryValueEx(key, "ProgId")[0].lower()
elif platform.system() == "Darwin":
    raw_browser = "safari"
else:
    raw_browser = webbrowser.get().name.lower()

if "chrome" in raw_browser:
    default_browser = "chrome"
elif "firefox" in raw_browser:
    default_browser = "firefox"
elif "safari" in raw_browser:
    default_browser = "safari"
elif "edge" in raw_browser:
    default_browser = "edge"
else:
    default_browser = "terminal"


@dataclass
class NotebookInit:
    """Initialisation data for a Notebook."""

    id: str
    name: str
    is_default: bool


class Index(Enum):
    """Index for accessing items in a collection."""

    Id = "id"
    Name = "name"


type IdOrNameIndex = str | slice[Index, str, None]
type EtreeExtractorDict = Mapping[str, EtreeExtractorDict | Callable[[Any], Any]]


def _flatten_dict(
    val: EtreeExtractorDict, prefix: str = ""
) -> dict[str, Callable[[Any], Any]]:
    """Flattens a nested dictionary.

    Args:
        val: The dictionary to flatten.
        prefix: The prefix to use for the keys.

    Returns:
        A flattened dictionary.
    """
    items: dict[str, Callable[[Any], Any]] = {}

    for _key, value in val.items():
        if len(_key) == 0:
            raise ValueError("Key cannot be empty string")

        key = f"{prefix}/{_key}"

        if callable(value):
            items[key] = value
        else:
            items.update(_flatten_dict(value, key))

    return items


def to_bool(s: str) -> bool:
    """Converts a string to a boolean.

    Args:
        s: The string to convert.

    Returns:
        The boolean value.
    """
    match s.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            raise ValueError(f"Cannot convert '{s}' to bool")


def _extract_etree(_etree: etree.Element, format: EtreeExtractorDict) -> dict[str, Any]:
    """Extracts data from an etree element.

    Args:
        etree: The etree element to extract data from.
        format: The format to use for extraction.

    Returns:
        A dictionary of extracted data.
    """
    flat = _flatten_dict(format)

    items: dict[str, Any] = {}

    for key, mapper in flat.items():
        value = _etree.findtext(f"./{key}")

        if (
            value is None
        ):  # XXX should we collate errors and return at end with the dict or?
            raise ValueError(f"Could not find value for './{key}'")

        try:
            items[key.split("/")[-1]] = mapper(value)
        except ValueError as err:
            raise ValueError(
                f"Could not map value {value} with {mapper.__name__} for './{key}'"
            ) from err

    return items


class User:
    """A LabArchives user."""

    def __init__(
        self,
        uid: str,
        auto_login: bool,
        notebooks: Sequence[NotebookInit],
        client: Client,
    ):
        super().__init__()
        self._id = uid
        self._can_refresh = auto_login
        self._notebooks = Notebooks(notebooks, self)
        self._client = client

    @property
    def id(self):
        return self._id

    @property
    def client(self):
        return self._client

    def api_get(self, api_method_uri: str | Sequence[str], **kwargs: Any):
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API.
        """
        return self._client.api_get(api_method_uri, **kwargs, uid=self._id)

    def api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str],
        **kwargs: Any,
    ):
        return self._client.api_post(api_method_uri, body, **kwargs, uid=self._id)

    def refresh(self, *, user_requested: bool = False):
        """Refreshes the user's session.

        Args:
            user_requested: Whether the refresh request is explicitly requested by the user
        """
        if not self._can_refresh and not user_requested:
            raise RuntimeError("User session cannot be automatically refreshed")

        uid_tree = self.api_get("users/user_info_via_id", authenticated=user_requested)
        self._id = uid_tree.findtext(".//users/id")  # TODO extract etree
        # XXX should we refresh ability to auto_login and notebooks here?

        # TODO fill in rest of function

    def get_max_upload_size(self) -> int:
        """Gets the maximum upload size for the user.

        Returns:
            The maximum upload size in bytes.
        """
        # NOTE the api reference doesn't explain what unit this is, so I'm going to treat this as bytes
        return _extract_etree(
            self.api_get("users/max_file_size"), {"max-file-size": int}
        )["max-file-size"]

    @property
    def notebooks(self):
        """The user's notebooks."""
        return self._notebooks


type NotebookNode = "NotebookPage | NotebookDirectory"


class MixinTreeCopy(ABC):
    @abstractmethod
    def copy_to(self, destination: Notebook | NotebookDirectory) -> NotebookNode:
        raise NotImplementedError


class NotebookEntity(ABC):
    """Base class for notebook entities."""

    def __init__(
        self,
        id: str,
        name: str,
        root: "Notebook",
        parent: NotebookTreeNode | None,
        can_read_comments: bool,
        can_write_comments: bool,
        can_read: bool,
        can_write: bool,
        user: "User",
    ):
        super().__init__()
        self._id = id
        self._name = name
        self._root = root
        self._parent = parent
        self._can_read_comments = can_read_comments
        self._can_write_comments = can_write_comments
        self._can_read = can_read
        self._can_write = can_write
        self._user = user

    @property
    def name(self) -> str:
        """The name of the entity."""
        return self._name  # TODO allow this to be set

    @property
    def id(self) -> str:
        """The ID of the entity."""
        return self._id

    @property
    @deprecated("This doesn't affect the API behavior")
    def can_read_comments(self) -> bool:
        """Whether the user can read comments on the entity."""
        return self._can_read_comments

    @property
    @deprecated("This doesn't affect the API behavior")
    def can_write_comments(self) -> bool:
        """Whether the user can write comments on the entity."""
        return self._can_write_comments

    @property
    @deprecated("This doesn't affect the API behavior")
    def can_read(self) -> bool:
        """Whether the user can read the entity."""
        return self._can_read

    @property
    @deprecated("This doesn't affect the API behavior")
    def can_write(self) -> bool:
        """Whether the user can write the entity."""
        return self._can_write

    @property
    def parent(self) -> NotebookTreeNode | None:
        """The parent of the entity."""
        return self._parent

    @property
    def root(self) -> "Notebook":
        """The root of the entity."""
        return self._root


class NotebookTreeNode(
    ABC, Mapping[IdOrNameIndex, NotebookNode | Sequence[NotebookNode]]
):
    """Base class for notebook tree nodes."""

    def __init__(self):
        super().__init__()
        self._children: MutableSequence[NotebookNode] = []
        self._populated: bool = False

    @abstractmethod
    def _populate(self) -> None:
        raise NotImplementedError

    def _ensure_populated(self):
        if not self._populated:
            self._populate()
            self._populated = True

    @override
    def __len__(self) -> int:
        self._ensure_populated()
        return len(self._children)

    @override
    def __iter__(self):
        self._ensure_populated()
        return iter(child.id for child in self._children)

    # TODO moving things around

    @overload
    def __getitem__(self, key: str) -> NotebookNode:
        pass

    @overload
    def __getitem__(self, key: "slice[Literal[Index.Id], str, None]") -> NotebookNode:
        pass

    @overload
    def __getitem__(
        self, key: "slice[Literal[Index.Name], str, None]"
    ) -> list[NotebookNode]:
        pass

    @override
    def __getitem__(self, key: IdOrNameIndex) -> NotebookNode | list[NotebookNode]:
        self._ensure_populated()

        if isinstance(key, slice):
            key_type = key.start
            key_value = key.stop
        else:
            key_type = Index.Id
            key_value = key

        match key_type:
            case Index.Id:
                for node in self._children:
                    if node.id == key_value:
                        return node
                raise KeyError(f"Node with id '{key_value}' not found")
            case Index.Name:
                return list(filter(lambda k: k.name == key_value, self._children))

    @abstractmethod
    def create_directory(self, name: str) -> "NotebookDirectory":
        raise NotImplementedError

    @abstractmethod
    def create_page(self, name: str) -> "NotebookPage":
        raise NotImplementedError


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

    def get_tree(self, parent: NotebookDirectory | Literal["0"]):
        """Gets the tree of a notebook.

        Args:
            parent: The parent of the tree.

        Returns:
            The tree of the notebook.
        """
        xml_tree = self._user.api_get(
            "tree_tools/get_tree_level",
            nbid=self.id,
            parent_tree_id=parent if parent == "0" else parent.id,
        )

        nodes: list["NotebookPage | NotebookDirectory"] = []

        for subtree in xml_tree.iterfind(".//level-node"):
            node = _extract_etree(
                subtree,
                {
                    "is-page": to_bool,
                    "tree-id": str,
                    "display-text": str,
                    "user-access": {
                        "can-read": to_bool,
                        "can-write": to_bool,
                        "can-read-comments": to_bool,
                        "can-write-comments": to_bool,
                    },
                },
            )  # TODO do we want to handle errors here?

            args = (
                node["tree-id"],
                node["display-text"],
                self,
                self if parent == "0" else parent,
                node["can-read-comments"],
                node["can-write-comments"],
                node["can-read"],
                node["can-write"],
                self._user,
            )

            if node["is-page"]:
                nodes.append(NotebookPage(*args))
            else:
                nodes.append(NotebookDirectory(*args))

        return nodes

    @override
    def _populate(self):
        self._children = self.get_tree("0")

    @override
    def create_page(self, name: str) -> NotebookPage:
        # TODO take into account whether can write in this directory
        create_tree = self._user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id="0",
            display_text=name,
            is_folder="false",
        )
        tree_id = _extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_page = NotebookPage(
            tree_id, name, self, self, True, True, True, True, self._user
        )
        self._children.append(new_page)
        return new_page

    @override
    def create_directory(self, name: str) -> NotebookDirectory:
        # TODO take into account whether can write in this directory
        create_tree = self._user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id="0",
            display_text=name,
            is_folder="true",
        )
        tree_id = _extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_dir = NotebookDirectory(
            tree_id, name, self, self, True, True, True, True, self._user
        )
        self._children.append(new_dir)
        return new_dir

    # get info # This is basically irrelevant
    # delete notebook?
    # metadata?
    # tree tools
    #    - ex search for specific page
    #    - etc.


class Notebooks(Mapping[IdOrNameIndex, Notebook | Sequence[Notebook]]):
    """A collection of notebooks."""

    def __init__(self, notebooks: Sequence[NotebookInit], user: User):
        super().__init__()
        self._user = user
        self._notebooks = [Notebook(n, user, self) for n in notebooks]
        self._notebooks_by_id = {n.id: n for n in self._notebooks}

    @overload
    def __getitem__(self, key: str) -> Notebook:
        pass

    @overload
    def __getitem__(self, key: "slice[Literal[Index.Id], str, None]") -> Notebook:
        pass

    @overload
    def __getitem__(
        self, key: "slice[Literal[Index.Name], str, None]"
    ) -> list[Notebook]:
        pass

    @override
    def __getitem__(self, key: IdOrNameIndex) -> Notebook | list[Notebook]:
        if isinstance(key, slice):
            key_type = key.start
            key_value = key.stop
        else:
            key_type = Index.Id
            key_value = key

        match key_type:
            case Index.Id:
                return self._notebooks_by_id[key_value]
            case Index.Name:
                return list(filter(lambda k: k.name == key_value, self._notebooks))

    @override
    def __iter__(self):
        return iter(map(lambda c: (c.id), self._notebooks))

    @override
    def __len__(self):
        return len(self._notebooks)

    @override
    def values(self):
        return self._notebooks_by_id.values()

    def create_notebook(self, name: str) -> Notebook:
        """Creates a new notebook.

        Args:
            name: The name of the notebook.

        Returns:
            The new notebook.
        """
        nbid = _extract_etree(
            self._user.api_get(
                "notebooks/create_notebook", name=name, initial_folders="Empty"
            ),
            {"nbid": str},
        )["nbid"]

        # TODO check that the notebook with same id does not already exist
        #      why though? that should never happen unless their api is broken

        new_notebook = Notebook(NotebookInit(nbid, name, False), self._user, self)

        self._notebooks.append(new_notebook)
        self._notebooks_by_id[nbid] = new_notebook

        return new_notebook


class NotebookDirectory(NotebookEntity, NotebookTreeNode, MixinTreeCopy):
    """A directory in a notebook."""

    @override
    def create_page(self, name: str) -> NotebookPage:
        if not self._can_write:
            raise RuntimeError("Action Not Allowed")  # TODO better error
        create_tree = self._user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id=self.id,
            display_text=name,
            is_folder="false",
        )
        tree_id = _extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_page = NotebookPage(
            tree_id, name, self._root, self, True, True, True, True, self._user
        )

        self._children.append(new_page)
        return new_page

    @override
    def create_directory(self, name: str) -> NotebookDirectory:
        if not self._can_write:
            raise RuntimeError("Action Not Allowed")  # TODO better error
        create_tree = self._user.api_get(
            "tree_tools/insert_node",
            nbid=self.id,
            parent_tree_id=self.id,
            display_text=name,
            is_folder="true",
        )
        tree_id = _extract_etree(create_tree, {"node": {"tree-id": str}})["tree-id"]

        new_dir = NotebookDirectory(
            tree_id, name, self._root, self, True, True, True, True, self._user
        )

        self._children.append(new_dir)
        return new_dir

    @override
    def _populate(self):
        self._children = self._root.get_tree(self)

    @override
    def copy_to(self, destination: Notebook | NotebookDirectory) -> NotebookNode:
        new_dir = destination.create_directory(self.name)

        for child in self._children:
            child.copy_to(new_dir)

        return new_dir


class NotebookPage(NotebookEntity, MixinTreeCopy):
    """A page in a notebook."""

    def __init__(
        self,
        id: str,
        name: str,
        root: Notebook,
        parent: NotebookTreeNode | None,
        can_read_comments: bool,
        can_write_comments: bool,
        can_read: bool,
        can_write: bool,
        user: User,
    ):
        super().__init__(
            id,
            name,
            root,
            parent,
            can_read_comments,
            can_write_comments,
            can_read,
            can_write,
            user,
        )
        self._entries = None

    @property
    def entries(self) -> Entries:
        """The entries on the page."""
        if self._entries is None:
            entries: list[Entry] = []

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

                entries.append(
                    Entry(
                        entry_data["eid"],
                        entry_data["part-type"],
                        entry_data["attach-file-name"],
                        entry_data["attach-content-type"],
                        entry_data["entry-data"],
                        self._user,
                    )
                )

            self._entries = Entries(entries, self._user, self)

        return self._entries

    @override
    def copy_to(self, destination: Notebook | NotebookDirectory) -> NotebookNode:
        new_page = destination.create_page(self.name)

        for entry in self.entries.values():
            new_page.entries.create_entry(
                entry._part_type,  # pyright: ignore[reportArgumentType, reportPrivateUsage]
                entry.content,
            )

        return new_page


class Entries(Mapping[str, "Entry"]):
    """A collection of entries."""

    def __init__(self, entries: Sequence[Entry], user: User, page: NotebookPage):
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

    def create_entry(
        self,
        entry_type: Literal["heading", "text entry", "plain text entry"],
        data: str,
    ) -> Entry:
        entry_tree = self._user.api_post(
            "entries/add_entry",
            {"entry_data": data},
            part_type=entry_type,
            pid=self._page.id,
            nbid=self._page.root.id,
        )

        id = _extract_etree(entry_tree, {"entry": {"eid": str}})["eid"]

        self._entries[id] = Entry(id, entry_type, "", "", data, self._user)

        return self._entries[id]

    # This class exists solely so we can add entries in future / delete them


T = TypeVar("T")


class Entry(ABC, Generic[T]):
    """An entry on a page."""

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


class BaseTextEntry(Entry[str], ABC):
    def __init__(self, eid: str, data: str, user: User):
        super().__init__(eid, user)
        self._entry_data = data

    @property
    @override
    def content(self) -> str:
        """The content of the entry."""
        return self._entry_data


class TextEntry(BaseTextEntry):
    @property
    @override
    def content_type(self) -> str:
        """The content type of the entry."""
        return "text entry"


class HeaderEntry(BaseTextEntry):
    @property
    @override
    def content_type(self) -> str:
        """The content type of the entry."""
        return "heading"


class PlainTextEntry(BaseTextEntry):
    @property
    @override
    def content_type(self) -> str:
        """The content type of the entry."""
        return "plain text entry"


class WidgetEntry(BaseTextEntry):
    @property
    @override
    def content_type(self) -> str:
        """The content type of the entry."""
        return "widget"


class AttachmentEntry(Entry[BufferedIOBase]):
    def __init__(self, eid: str, caption: str, user: User):
        super().__init__(eid, user)
        self._caption = caption
        self._data = None

    @property
    @override
    def content_type(self) -> str:
        """The content type of the entry."""
        return "Attachment"

    @property
    @override
    def content(self) -> BufferedIOBase:
        """The content of the entry."""
        if self._data is None:
            attachment = get(
                self._user.client.construct_url(
                    "entries/entry_attachment",
                    {  # TODO move into client
                        "uid": self._user.id,
                        "eid": self.id,
                    },
                ),
                stream=True,
            )

            content_type = (  # noqa: F841
                attachment.headers.get("Content-Type") or "application/octet-stream"
            )
            filename = attachment.headers.get("Content-Disposition")

            assert filename is not None  # TODO

            filename = tuple(
                k.split("=")[1].strip('"')
                for k in filename.split(";")
                if k.strip().startswith("filename")
            )[0]

            return  # TODO
        return self._data


class Comment:
    """A comment on an entity."""

    pass


class Client:
    """A client for the LabArchives API."""

    def __init__(self, base_url: str, akid: str, akpass: bytes | str):
        super().__init__()
        self._base_url = urlsplit(base_url).geturl()
        self._akid = akid
        self._hmac = HMAC(
            bytes(akpass, "utf8") if isinstance(akpass, str) else akpass, SHA512()
        )

    def generate_auth_url(self, redirect_url: str) -> str:
        """Generates a URL for authentication.

        Args:
            redirect_url: The URL to redirect to after authentication.

        Returns:
            The authentication URL.
        """
        return self.construct_url(
            "api_user_login",
            {"redirect_uri": redirect_url},
            should_prefix_api=False,
            signature_method=redirect_url,
        )

    def login_authcode(self, user_email: str, auth_code: str):
        """Logs in a user with an authentication code.

        Args:
            user_email: The user's email address.
            auth_code: The authentication code.

        Returns:
            A User object.
        """
        uid_tree = self.api_get(
            "users/user_access_info", login_or_email=user_email, password=auth_code
        )

        uid = itemgetter(
            "id",
            # "auto-login-allowed"
        )(
            _extract_etree(
                uid_tree,
                {
                    "id": str,
                    # "auto-login-allowed": to_bool
                },
            )
        )

        notebooks: list[NotebookInit] = []

        for notebook in uid_tree.iterfind(".//notebook"):
            notebook_id, notebook_name, is_default = itemgetter(
                "id", "name", "is-default"
            )(_extract_etree(notebook, {"id": str, "name": str, "is-default": to_bool}))

            # TODO error or warning when id/name are failed?

            notebooks.append(NotebookInit(notebook_id, notebook_name, is_default))

        notebooks.sort(key=lambda k: k.is_default)

        return User(uid, False, notebooks, self)

    def api_get(
        self, api_method_uri: str | Sequence[str], **kwargs: Any
    ) -> etree.Element:
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API as an etree element.
        """
        request = get(self.construct_url(api_method_uri, query=kwargs))

        if request.status_code != status_codes.ok:
            raise RuntimeError(  # TODO make this more useful
                f"API request failed with status code {request.status_code}: {request.text}"
            )
            # See https://mynotebook.labarchives.com/share/LabArchives%2520API/NDEuNnwyNy8zMi9UcmVlTm9kZS83NDE1Mjk1NTJ8MTA1LjY= [ELN Error Codes]

        return etree.fromstring(bytes(request.text, encoding="utf-8"))

    def api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str],
        **kwargs: Any,
    ) -> etree.Element:
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API as an etree element.
        """
        request = post(self.construct_url(api_method_uri, query=kwargs), data=body)

        if request.status_code != status_codes.ok:
            raise RuntimeError(  # TODO make this more useful
                f"API request failed with status code {request.status_code}: {request.text}"
            )
            # See https://mynotebook.labarchives.com/share/LabArchives%2520API/NDEuNnwyNy8zMi9UcmVlTm9kZS83NDE1Mjk1NTJ8MTA1LjY= [ELN Error Codes]

        return etree.fromstring(bytes(request.text, encoding="utf-8"))

    def default_authenticate(self) -> User:
        """Authenticates a user using the default browser and localhost server.

        Returns:
            An authenticated user.
        """
        auth_url = self.generate_auth_url("http://localhost:8089/")

        driver = None
        options = None

        match default_browser:
            case "chrome":
                options = webdriver.ChromeOptions()
                driver = webdriver.Chrome(options=options)
                print("Opening Chrome for authentication...")
            case "firefox":
                options = webdriver.FirefoxOptions()
                driver = webdriver.Firefox(options=options)
                print("Opening Firefox for authentication...")
            case "safari":
                options = webdriver.SafariOptions()
                driver = webdriver.Safari(options=options)
                print("Opening Safari for authentication...")
            case "edge":
                options = webdriver.EdgeOptions()
                driver = webdriver.Edge(options=options)
                print("Opening Edge for authentication...")
            case _:
                print("Open authentication URL in your browser:")
                print(auth_url)

        if driver is not None:
            driver.get(auth_url)
            print("Please complete the authentication in the opened browser window...")

        user = self.collect_auth_response()

        if driver is not None:
            driver.quit()

        return user

    def collect_auth_response(self) -> User:
        """Launches default localhost server at 8089 to collect LabArchives Authentication Response.

        Returns:
            An authenticated user.
        """

        auth_info: dict[str, str] = {}

        class AuthRequestHandler(SimpleHTTPRequestHandler):
            @override
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                _s, _n, _p, querystring, _f = urlsplit(self.path)

                query = dict(parse_qsl(querystring))

                if "error" in query:
                    self.wfile.write(
                        bytes(f"Error: {query['error']}", encoding="utf-8")
                    )
                else:
                    self.wfile.write(b"Thanks for Authenticating. Close this Window")
                    auth_info["auth_code"] = query["auth_code"]
                    auth_info["email"] = query["email"]

            @override
            def log_message(self, format: str, *args: Any) -> None:
                pass

        with TCPServer(("127.0.0.1", 8089), AuthRequestHandler) as httpd:
            httpd.handle_request()

        return self.login_authcode(auth_info["email"], auth_info["auth_code"])

    def construct_url(
        self,
        api_method_uri: str | Sequence[str],
        query: Mapping[str, Any],
        expires_in: timedelta | datetime | None = None,
        *,
        should_prefix_api: bool = True,
        signature_method: str | None = None,
    ):
        """Constructs a URL for the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            query: The query string parameters.
            expires_in: The expiration time for the URL.
            should_prefix_api: Whether to prefix the API method with "api".
            signature_method: The signature method to use.

        Returns:
            The constructed URL.
        """
        if isinstance(api_method_uri, str):
            api_method_uri = api_method_uri.split("/")

        method_parts = tuple(filter(lambda k: len(k.strip()) != 0, api_method_uri))

        if should_prefix_api:
            if method_parts[0] != "api":
                method_parts = ["api", *method_parts]
        else:
            if method_parts[0] == "api":
                method_parts = method_parts[1:]

        api_method = method_parts[-1] if signature_method is None else signature_method

        scheme, netloc, path, _qs, _f = urlsplit(self._base_url)

        if not path.endswith("/"):
            path += "/"

        path += "/".join(method_parts)

        if expires_in:
            return self._sign_url(
                urlunsplit((scheme, netloc, path, urlencode(query), _f)),
                api_method,
                expires_in,
            )
        else:
            return self._sign_url(
                urlunsplit((scheme, netloc, path, urlencode(query), _f)),
                api_method,
            )

    def _signature(self, api_method: str, expiry: int) -> str:
        hmac = self._hmac.copy()

        hmac.update(f"{self._akid}{api_method}{expiry}".encode())

        sig_raw = hmac.finalize()

        return b64encode(sig_raw).decode()

    def _sign_url(
        self,
        url: str,
        api_method: str,
        expires_in: timedelta | datetime = timedelta(seconds=60),
    ) -> str:
        scheme, netloc, path, querystring, _f = urlsplit(url)
        query = dict(parse_qsl(querystring))

        if isinstance(expires_in, timedelta):
            expiry = round((datetime.now() + expires_in).timestamp() * 1000)
        else:
            expiry = round(expires_in.timestamp() * 1000)
        sig = self._signature(api_method, expiry)

        query["akid"] = self._akid
        query["expires"] = str(expiry)
        query["sig"] = sig

        return urlunsplit((scheme, netloc, path, urlencode(query), _f))
