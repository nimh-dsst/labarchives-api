from urllib.parse import urlsplit, urlunsplit, quote, urlencode, parse_qsl
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA512
from base64 import b64encode
from requests import get
from datetime import timedelta, datetime
from lxml import etree

class User:
    def __init__(self, uid: str, auto_login: bool, notebooks: list[dict[str, any]], client: Client):
        self.uid = uid
        self.can_refresh = auto_login
        self.notebooks = notebooks
        self.client = client

    def refresh(self, *, authenticated=False):
        if not self.can_refresh and not authenticated:
            raise "Cannot" # TODO
        refresh_request = get(self.client.construct_url("users/user_info_via_id", {"uid": self.uid, "authenticated":authenticated}))

        # TODO handle failure

        uid_tree = etree.fromstring(refresh_request.text)

        self.uid = uid_tree.findtext(".//users/id")
        # XXX should we refresh ability to auto_login and notebooks here?

    

class Client:

    def __init__(self, base_url: str, akid: str, akpass: bytes | str):
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
        auto_login = bool(uid_tree.findtext(".//users/auto-login-allowed"))

        notebooks = []
        
        for notebook in uid_tree.iterfind(".//notebook"):
            notebook_id = notebook.findtext('./id')

            notebooks.append({
                "id": notebook_id, 
                "name": notebook.findtext('./name'),
                "default": bool(notebook.findtext('./is-default'))
            })

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
        



