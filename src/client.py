from operator import itemgetter
from typing import Any, Generator, Mapping, Sequence, override
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from requests import Response, get, post
from requests import codes as status_codes

from user import User
from util.extract import extract_etree, to_bool
from util.notebookinit import NotebookInit

from io import BufferedIOBase

from lxml.etree import Element, fromstring
from base64 import b64encode
from datetime import datetime, timedelta
from socketserver import TCPServer
from http.server import SimpleHTTPRequestHandler

import selenium.webdriver as webdriver

from browser import default_browser


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
            extract_etree(
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
            )(extract_etree(notebook, {"id": str, "name": str, "is-default": to_bool}))

            # TODO error or warning when id/name are failed?

            notebooks.append(NotebookInit(notebook_id, notebook_name, is_default))

        notebooks.sort(key=lambda k: k.is_default)

        return User(uid, False, notebooks, self)

    @staticmethod
    def _handle_request_status(response: Response) -> None:
        if response.status_code != status_codes.ok:
            raise RuntimeError(  # TODO make this more useful
                f"API request failed with status code {response.status_code}: {response.text}"
            )
            # See https://mynotebook.labarchives.com/share/LabArchives%2520API/NDEuNnwyNy8zMi9UcmVlTm9kZS83NDE1Mjk1NTJ8MTA1LjY= [ELN Error Codes]

    def stream_api_get(
        self, api_method_uri: str | Sequence[str], **kwargs: Any
    ) -> Generator[bytes, None, Response]:
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API as a stream of bytes.
        """
        with get(
            self.construct_url(api_method_uri, query=kwargs), stream=True
        ) as request:
            Client._handle_request_status(request)

            for chunk in request.iter_content(1024 * 1024):
                yield chunk

            return request

    def stream_api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ) -> Generator[bytes, None, Response]:
        """Makes a POST request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API as a stream of bytes.
        """
        with post(
            self.construct_url(api_method_uri, query=kwargs), data=body, stream=True
        ) as request:
            Client._handle_request_status(request)

            for chunk in request.iter_content(1024 * 1024):
                yield chunk

            return request

    def raw_api_get(
        self, api_method_uri: str | Sequence[str], **kwargs: Any
    ) -> Response:
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API.
        """
        request = get(self.construct_url(api_method_uri, query=kwargs))
        Client._handle_request_status(request)

        return request

    def raw_api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ) -> Response:
        """Makes a POST request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API.
        """
        request = post(self.construct_url(api_method_uri, query=kwargs), data=body)
        Client._handle_request_status(request)

        return request

    def api_get(self, api_method_uri: str | Sequence[str], **kwargs: Any) -> Element:
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API as an etree element.
        """

        return fromstring(
            bytes(self.raw_api_get(api_method_uri, **kwargs).text, encoding="utf-8")
        )

    def api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ) -> Element:
        """Makes a POST request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API as an etree element.
        """

        return fromstring(
            bytes(
                self.raw_api_post(api_method_uri, body, **kwargs).text, encoding="utf-8"
            )
        )

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
            case "edge":
                options = webdriver.EdgeOptions()
                driver = webdriver.Edge(options=options)
                print("Opening Edge for authentication...")
            case "terminal":
                print("Open authentication URL in your browser:")
                print(auth_url)
            case _:
                print(
                    "WARNING: No compatible browser detected (chrome, firefox, edge), defaulting to terminal"
                )
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

        url = urlunsplit((scheme, netloc, path, urlencode(query), _f))

        if expires_in:
            return self._sign_url(url, api_method, expires_in)
        else:
            return self._sign_url(url, api_method)

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
