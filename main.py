from urllib.parse import urlsplit, urlunsplit, quote, urlencode, parse_qsl
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA512
from base64 import b64encode
from requests import get
from datetime import timedelta, datetime
from lxml import etree
from copy import deepcopy
from dataclasses import dataclass
from abs import ABC, abstractmethod
from collections.abc import MutableMapping

@dataclass
class NotebookInfo:
    id: str
    name: str
    is_default: bool

class User:
    def __init__(self, uid: str, auto_login: bool, notebooks: list[NotebookInfo], client: Client):
        self._uid = uid
        self._can_refresh = auto_login
        self._notebooks = Notebooks(notebooks, self, client)
        self._client = client

    """
    Utility method to automatically integrate client uid
    """
    def _construct_client_url(self, api_method_uri: str | list[str], query: dict[str, any], expires_in: timedelta | datetime = None):
        _query = deepcopy(query)

        if "uid" not in _query:
            _query["uid"] = self._uid
        
        return self._client.construct_url(api_method, _query, expires_in)

    def refresh(self, *, authenticated=False):
        if not self._can_refresh and not authenticated:
            raise "Cannot Automatically Refresh" # TODO
        refresh_request = get(self._construct_client_url("users/user_info_via_id", {"authenticated":authenticated}))

        # TODO handle failure

        uid_tree = etree.fromstring(refresh_request.text)

        self.uid = uid_tree.findtext(".//users/id")
        # XXX should we refresh ability to auto_login and notebooks here?

        # TODO

    def get_max_upload_size() -> int:
        # NOTE the api reference doesn't explain what unit this is, so I'm going to treat this as bytes
        size_request = get(self._construct_client_url("users/max_file_size")

        # TODO handle failure
        # TODO centralize requests through the client so the client can handle request failures there, and just let its Exceptions do the handling
        # NOTE based on usage patterns im seeing while writing this I think the user should probably also handle requests requiring its uid, or patch over the client's request handling

        size_tree = etree.fromstring(size_request.text)

        # TODO handle conversion failure
        max_filesize = int(size_tree.findtext(".//max-file-size"))

        return max_filesize  

    @property
    def notebooks(self):
        return self._notebooks

class Notebooks: # TODO inherit from mapping and iterable?
    def __init__(self, notebooks: list[NotebookInfo], user: User, client: Client):
        self._user = user
        self._client = client
        self._notebooks = [Notebook(n, user, client) for n in notebooks]
        self._notebooks_by_id = {n.id: n for n in self._notebooks}
        self._notebooks_by_name = {n.name: n] for n in self._notebooks}

    def __getitem__(self, key):
        if isinstance(key, slice):
            # TODO evaluate the usage of enum values here
            key_type = key.start
            key_value = key.stop
        else:
            key_type = "id"
            key_value = key

        # NOTE assumes only possible key types are id and name
        notebooks_reference = self._notebooks if key_type == "id" else self._notebooks_by_name

        return notebooks_reference[key_value]

    def __iter__(self):
        return self._notebooks.__iter__()
        
    # create notebook
    # XXX are there any other things we want off this?

class NotebookNode(ABC, MutableMapping):
    # acts as a dict
    # should assigns be implemented? (MutableMapping) or delegated to a function?
    # would need Page/Directory Inits to be passed for assigns, or-- Notebook with NoneType created with factory constructor?
    # need to retain data that this is an inorder list behind the scenes
    # TODO inherit from iterator?
    
    pass

@dataclass
class NotebookItem(ABC):
    _can_read_comments: bool
    _can_write_comments: bool
    _can_read: bool
    _can_write: bool

    @property
    def can_read_comments(self):
        return self._can_read_comments

    @property
    def can_write_comments(self):
        return self._can_write_comments

    @property
    def can_read(self):
        return self._can_read

    @property
    def can_write(self):
        return self._can_write


class Notebook(NotebookNode):
    def __init__(self, init: NotebookInfo, user, client):
        self._id = init.id
        self._name = init.name
        self._is_default = init.is_default

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @property
    def is_default(self): # FIXME what is this for anyways??
        return self._is_default
        
    # get info
    # modify info
    # get users
    # change user perms
    # del users
    # delete notebook?
    # metadata?
    # transfer ownership?
    # tree tools
    #    - ex search for specific page
    #    - etc.

    

class NotebookDirectory(NotebookItem, NotebookNode):
    pass

class NotebookPage(NotebookItem):
    pass

class Entry:
    pass



class Client:

    def __init__(self, base_url: str, akid: str, akpass: bytes | str):
        # TODO private the vars
        self.base_url = urlsplit(base_url).geturl()
        self.akid = akid
        self.hmac = HMAC(akpass if isinstance(akpass, bytes) else bytes(akpass, 'utf8'), SHA512())

    def generate_auth_url(self, redirect_url: str) -> str:
        return self.construct_url("api_user_login", {"redirect_uri": redirect_url}, 
                                  should_prefix_api=False, signature_method=redirect_url)

    def login_authcode(self, user_email: str, auth_code: str):
        uid_request = get(self.construct_url(
            "users/user_access_info", 
            {
                "login_or_email": user_email,
                "password": auth_code
            }
        ))

        # TODO handle failure

        uid_tree = etree.fromstring(uid_request.text)

        uid = uid_tree.findtext(".//users/id")

        # TODO handle conversion failure
        auto_login = bool(uid_tree.findtext(".//users/auto-login-allowed"))

        notebooks = []
        
        for notebook in uid_tree.iterfind(".//notebook"):
            notebook_id = notebook.findtext('./id')
            notebook_name = notebook.findtext('./name')
            is_default = bool(notebook.findtext('./is-default')) # TODO handle conversion failure

            notebooks.append(NotebookInfo(notebook_id, notebook_name, is_default))

        notebooks.sort(key=lambda k: k["default"])

        return User(uid, auto_login, notebooks, self)


    def login_token(self):
        # TODO see login_authcode, it's that but with a different name

        pass

    def construct_url(self, api_method_uri: str | list[str], query: dict[str, any], expires_in: timedelta | datetime = None, *,
                            should_prefix_api: bool = True, signature_method: str = None):
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

        scheme, netloc, path, _qs, _f = urlsplit(self.base_url)

        if not path.endswith('/'):
            path += '/'

        path += "/".join(method_parts)

        return self._sign_url(urlunsplit((scheme, netloc, path, urlencode(query), _f)), api_method, expires_in)
        
    def _signature(self, api_method: str, expiry: int) -> str:
        hmac = self.hmac.copy()

        hmac.update(f'{self.akid}{api_method}{expiry}'.encode())

        sig_raw = hmac.finalize()

        return b64encode(sig_raw).decode()


    def _sign_url(self, url: str, api_method: str, expires_in: timedelta | datetime = None) -> str:
        if expires_in is None: 
            expires_in = timedelta(seconds=60)

        scheme, netloc, path, querystring, _f = urlsplit(url)
        query = dict(parse_qsl(querystring))

        if isinstance(expires_in, timedelta):
            expiry = round((datetime.now() + expires_in).timestamp() * 1000)
        else:
            expiry = round(expires_in.timestamp() * 1000)
        sig = self._signature(api_method, expiry)

        query["akid"] = self.akid
        query["expires"] = str(expiry)
        query["sig"] = sig

        return urlunsplit((scheme, netloc, path, urlencode(query), _f))
        



