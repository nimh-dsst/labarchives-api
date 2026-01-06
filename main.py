from __future__ import annotations

from abc import ABC, abstractmethod
from base64 import b64encode
from collections.abc import Mapping, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from operator import itemgetter

from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from lxml import etree
from requests import codes as status_codes
from requests import get


@dataclass
class NotebookInit:
    id: str
    name: str
    is_default: bool


class Index(Enum):
    Id = 1
    Name = 2


type IdOrNameIndex = str | slice[Index, str, None]
type EtreeExtractorDict = Mapping[str, EtreeExtractorDict | Callable[[Any], Any]]


def _flatten_dict(
    val: EtreeExtractorDict, prefix: str = ""
) -> dict[str, Callable[[Any], Any]]:
    items: dict[str, Callable[[Any], Any]] = {}

    for _key, value in val.items():
        if len(_key) == 0:
            raise  # TODO raise exc for invalid value

        key = f"{prefix}/{_key}"

        if callable(value):
            items[key] = value
        else:
            items.update(_flatten_dict(value, key))

    return items


def to_bool(s: str) -> bool:
    match s.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            raise ValueError  # TODO


def _extract_etree(etree: etree.Element, format: EtreeExtractorDict) -> dict[str, Any]:
    flat = _flatten_dict(format)

    items: dict[str, Any] = {}

    for key, mapper in flat.items():
        value = etree.findtext(f"./{key}")

        if (
            value is None
        ):  # XXX should we collate errors and return at end with the dict or?
            raise  # TODO raise missing value exc
        try:
            items[key.split("/")[-1]] = mapper(value)
        except ValueError as err:
            raise err  # TODO raise invalid value exc

    return items


class User:
    def __init__(
        self,
        uid: str,
        auto_login: bool,
        notebooks: Sequence[NotebookInit],
        client: Client,
    ):
        self._uid = uid
        self._can_refresh = auto_login
        self._notebooks = Notebooks(notebooks, self)
        self._client = client

    def api_get(self, api_method_uri: str | Sequence[str], **kwargs: Any):
        return self._client.api_get(api_method_uri, **kwargs, uid=self._uid)

    # def api_post(self, api_method_uri: str | Sequence[str], **kwargs):
    # return self._client.api_post(api_method_uri, **kwargs, uid=self.uid)

    def refresh(self, *, authenticated: bool = False):
        if not self._can_refresh and not authenticated:
            raise RuntimeError  # "Cannot Automatically Refresh"  # TODO fill in error

        uid_tree = self.api_get("users/user_info_via_id", authenticated=authenticated)
        self._uid = uid_tree.findtext(".//users/id")  # TODO extract etree
        # XXX should we refresh ability to auto_login and notebooks here?

        # TODO fill in rest of function

    def get_max_upload_size(self) -> int:
        # NOTE the api reference doesn't explain what unit this is, so I'm going to treat this as bytes
        return _extract_etree(
            self.api_get("users/max_file_size"), {"max-file-size": int}
        )["max-file-size"]

    @property
    def notebooks(self):
        return self._notebooks


type NotebookNode = "NotebookPage | NotebookDirectory"


class NotebookEntity(ABC):
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
        return self._name  # TODO allow this to be set

    @property
    def id(self) -> str:
        return self._id

    @property
    def can_read_comments(self) -> bool:
        return self._can_read_comments

    @property
    def can_write_comments(self) -> bool:
        return self._can_write_comments

    @property
    def can_read(self) -> bool:
        return self._can_read

    @property
    def can_write(self) -> bool:
        return self._can_write

    @property
    def parent(self) -> NotebookTreeNode | None:
        return self._parent

    @property
    def root(self) -> "Notebook":
        return self._root


class NotebookTreeNode(
    ABC, Mapping[IdOrNameIndex, NotebookNode | Sequence[NotebookNode]]
):
    def __init__(self):
        super().__init__()
        self._children: Sequence[NotebookNode]
        self._populated: bool = False

    @abstractmethod
    def _populate(self) -> None:
        raise NotImplementedError

    def _ensure_populated(self):
        if not self._populated:
            self._populate()
            self._populated = True

    def __len__(self) -> int:
        self._ensure_populated()
        return len(self._children)

    def __iter__(self):
        self._ensure_populated()
        return iter(child.id for child in self._children)

    # TODO moving things around

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
                raise KeyError  # TODO exc type
            case Index.Name:
                return list(filter(lambda k: k.name == key_value, self._children))


class Notebook(NotebookTreeNode):
    def __init__(self, init: NotebookInit, user: User, notebooks: Notebooks):
        self._id = init.id
        self._name = init.name
        self._is_default = init.is_default
        self._user = user
        self._notebooks = notebooks
        self._inserts_from_bottom: bool | None = None

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: str):
        self._user.api_get("notebooks/modify_notebook_info", nbid=self.id, name=value)

        self._name = value

    @property
    def inserts_from_bottom(self) -> bool:
        if self._inserts_from_bottom is None:
            self._inserts_from_bottom = not _extract_etree(
                self._user.api_get("notebooks/notebook_info", nbid=self.id),
                {"notebook": {"add-entry-to-page-top": to_bool}},
            )["add-entry-to-page-top"]

        return self._inserts_from_bottom

    @property
    def is_default(self):  # FIXME what is this for anyways??
        return self._is_default

    def get_tree(self, parent: NotebookDirectory | Literal["0"]):
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

    def _populate(self):
        self._children = self.get_tree("0")

    # get info # This is basically irrelevant
    # delete notebook?
    # metadata?
    # tree tools
    #    - ex search for specific page
    #    - etc.


class Notebooks(Mapping[IdOrNameIndex, Notebook | Sequence[Notebook]]):
    def __init__(self, notebooks: Sequence[NotebookInit], user: User):
        self._user = user
        self._notebooks = [Notebook(n, user, self) for n in notebooks]
        self._notebooks_by_id = {n.id: n for n in self._notebooks}

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

    def __iter__(self):
        return iter(map(lambda c: (c.id), self._notebooks))

    def __len__(self):
        return self._notebooks.__len__()

    def create_notebook(self, name: str) -> Notebook:
        nbid = _extract_etree(
            self._user.api_get(
                "notebooks/create_notebook", name=name, initial_folders="Empty"
            ),
            {"nbid": str},
        )["nbid"]

        new_notebook = Notebook(NotebookInit(nbid, name, False), self._user, self)

        self._notebooks.append(new_notebook)
        self._notebooks_by_id[nbid] = new_notebook

        return new_notebook


class NotebookDirectory(NotebookEntity, NotebookTreeNode):
    def _populate(self):
        self._children = self._root.get_tree(self)


class NotebookPage(NotebookEntity):
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

            self._entries = Entries(entries)

        return self._entries


class Entries(Mapping[str, "Entry"]):
    def __init__(self, entries: Sequence[Entry]):
        self._entries = {entry.id: entry for entry in entries}

    def __getitem__(self, key: str):
        return self._entries[key]

    def __iter__(self):
        return iter(self._entries)

    def __len__(self):
        return len(self._entries)

    def values(self):
        return self._entries.values()

    def items(self):
        return self._entries.items()

    def keys(self):
        return self._entries.keys()

    # This class exists solely so we can add entries in future / delete them


class Entry:
    # TODO perms
    def __init__(
        self,
        eid: str,
        part_type: str,
        filename: str,
        mimeType: str,
        data: str,
        user: User,
    ):
        self._id = eid
        self._user = user
        self._part_type = part_type
        match part_type.lower():
            case "attachment":
                raise NotImplementedError
            case (
                "plain text entry"
                | "text entry"
                | "widget entry"
                | "sketch entry"
                | "heading"
                | "equation entry"
            ):
                self._content_type = "text"
                self._content = data
            case "reference entry":
                self._content_type = "xml"
                self._content = etree.fromstring(data)
            case "assignment entry" | _:
                raise NotImplementedError

    @property
    def id(self):
        return self._id

    @property
    def content_type(self) -> str:
        return self._content_type

    @property
    def content(self) -> str | etree.Element:
        return self._content


class Comment:
    pass


class Client:
    def __init__(self, base_url: str, akid: str, akpass: bytes | str):
        self._base_url = urlsplit(base_url).geturl()
        self._akid = akid
        self._hmac = HMAC(
            bytes(akpass, "utf8") if isinstance(akpass, str) else akpass, SHA512()
        )

    def generate_auth_url(self, redirect_url: str) -> str:
        return self.construct_url(
            "api_user_login",
            {"redirect_uri": redirect_url},
            should_prefix_api=False,
            signature_method=redirect_url,
        )

    def login_authcode(self, user_email: str, auth_code: str):
        uid_tree = self.api_get(
            "users/user_access_info", login_or_email=user_email, password=auth_code
        )

        uid, auto_login = itemgetter("uid", "auto-login-allowed")(
            _extract_etree(
                uid_tree, {"users": {"id": str, "auto-login-allowed": to_bool}}
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

        return User(uid, auto_login, notebooks, self)

    def api_get(
        self, api_method_uri: str | Sequence[str], **kwargs: Any
    ) -> etree.Element:
        request = get(self.construct_url(api_method_uri, query=kwargs))

        if request.status_code != status_codes.ok:
            pass  # TODO error
            # See https://mynotebook.labarchives.com/share/LabArchives%2520API/NDEuNnwyNy8zMi9UcmVlTm9kZS83NDE1Mjk1NTJ8MTA1LjY= [ELN Error Codes]

        return etree.fromstring(request.text)

    # def api_post():
    #    pass  # TODO fill in function

    def construct_url(
        self,
        api_method_uri: str | Sequence[str],
        query: Mapping[str, Any],
        expires_in: timedelta | datetime | None = None,
        *,
        should_prefix_api: bool = True,
        signature_method: str | None = None,
    ):
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
