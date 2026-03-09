"""
LabArchives API Client.

This module provides the core client for interacting with the LabArchives API,
handling authentication, request signing, and various API call methods.
"""

from __future__ import annotations
import warnings
from operator import itemgetter
from typing import Any, Generator, Mapping, Sequence, override
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from os import getenv

from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from requests import codes as status_codes, Response, Session
from requests.adapters import HTTPAdapter
import ssl

from .user import User
from .util import extract_etree, to_bool, NotebookInit

from io import BufferedIOBase

from lxml.etree import Element, fromstring
from base64 import b64encode
from datetime import datetime, timedelta
from socketserver import TCPServer
from http.server import SimpleHTTPRequestHandler

from .browser import default_browser

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


context = ssl.create_default_context()


class _313HTTPAdapter(HTTPAdapter):
    """Custom HTTP adapter that disables strict X.509 certificate verification.

    This adapter is used to work around certain SSL certificate validation issues
    by disabling the VERIFY_X509_STRICT flag. This allows the client to connect
    to servers with certificates that might not pass strict validation.

    .. warning::
       This reduces security by relaxing certificate validation. Use only when
       necessary and with trusted servers.
    """

    def init_poolmanager(self, *args: Any, **kwargs: Any):
        """Initializes the connection pool manager with custom SSL context.

        This method overrides the default pool manager initialization to inject
        a custom SSL context that disables strict X.509 verification.

        :param args: Positional arguments to pass to the parent init_poolmanager.
        :param kwargs: Keyword arguments to pass to the parent init_poolmanager.
        """
        context = ssl.create_default_context()
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT

        super().init_poolmanager(*args, **kwargs, ssl_context=context)  # pyright: ignore[reportUnknownMemberType]


class Client:
    """
    A client for the LabArchives API.

    This class handles the connection to the LabArchives API
    and provides methods for making authenticated API calls.
    It also manages the authentication flow.
    """

    def __init__(
        self,
        base_url: str | None = None,
        akid: str | None = None,
        akpass: bytes | str | None = None,
        *,
        strict_cert: bool = True,
    ):
        """
        Initializes a new LabArchives API client.

        If any parameter is None, the client will attempt to load values from
        a ``.env`` file using ``python-dotenv``. The environment variables used are:

        - ``API_URL``: The base URL (defaults to ``https://api.labarchives.com``).
        - ``ACCESS_KEYID``: The Access Key ID.
        - ``ACCESS_PWD``: The Access Key Password.

        :param base_url: The base URL of the LabArchives API (e.g., "https://mynotebook.labarchives.com").
                         If None, loaded from the ``API_URL`` environment variable.
        :param akid: The Access Key ID for API authentication.
                     If None, loaded from the ``ACCESS_KEYID`` environment variable.
        :param akpass: The Access Key Password for HMAC-SHA512 signing.
                       If None, loaded from the ``ACCESS_PWD`` environment variable.
        :param strict_cert: Whether to use strict X.509 certificate verification.
                           If False, disables the VERIFY_X509_STRICT flag to allow connections
                           to servers with certificates that may not pass strict validation.
                           Defaults to True. **Warning:** Setting this to False reduces security.
        """
        super().__init__()

        if base_url is None or akid is None or akpass is None:
            if base_url is None:
                base_url = getenv("API_URL", "https://api.labarchives.com")
            if akid is None:
                akid = getenv("ACCESS_KEYID")
            if akpass is None:
                akpass = getenv("ACCESS_PWD")

        if not akid or not akpass:
            raise RuntimeError(
                "ACCESS_KEYID or ACCESS_PWD environment variables not set."
            )

        self._base_url = urlsplit(base_url).geturl()
        self._akid = akid
        self._hmac = HMAC(
            bytes(akpass, "utf8") if isinstance(akpass, str) else akpass, SHA512()
        )
        self.session = Session()
        if not strict_cert:
            self.session.mount("https://", _313HTTPAdapter())

    def generate_auth_url(self, redirect_url: str) -> str:
        """
        Generates a URL for authenticating with the LabArchives API.

        This URL is used to initiate the authorization code flow,
        redirecting the user to LabArchives to grant permissions.

        :param redirect_url: The URL to which LabArchives will redirect the user
                             after successful authentication, containing the authorization code.
        :returns: The full authentication URL.
        """
        return self.construct_url(
            "api_user_login",
            {"redirect_uri": redirect_url},
            should_prefix_api=False,
            signature_method=redirect_url,
        )

    def login(self, user_email: str, auth_code: str) -> User:
        """
        Logs in a user using an authentication code. This can be from the standard
        authentication flow or a one-hour code from the LabArchives website.

        This method exchanges the authorization code for user access information,
        including their user ID and available notebooks.

        :param user_email: The email address of the authenticating user.
        :param auth_code: The authorization code received from LabArchives.
        :returns: A :class:`~labapi.user.User` object representing the authenticated user session.
        """
        uid_tree = self.api_get(
            "users/user_access_info", login_or_email=user_email, password=auth_code
        )

        uid = itemgetter("id")(extract_etree(uid_tree, {"id": str}))

        notebooks: list[NotebookInit] = []

        for notebook in uid_tree.iterfind(".//notebook"):
            try:
                notebook_id, notebook_name, is_default = itemgetter(
                    "id", "name", "is-default"
                )(
                    extract_etree(
                        notebook, {"id": str, "name": str, "is-default": to_bool}
                    )
                )
            except ValueError as e:
                warnings.warn(f"Failed to parse notebook entry: {e}")
                continue

            notebooks.append(NotebookInit(notebook_id, notebook_name, is_default))

        notebooks.sort(key=lambda k: k.is_default)

        return User(uid, user_email, notebooks, self)

    @staticmethod
    def _handle_request_status(response: Response) -> None:
        """
        Handles the HTTP response status, raising an error for unsuccessful requests.

        :param response: The HTTP response object from the requests library.
        :raises RuntimeError: If the HTTP status code is not 200 (OK).
        """
        if response.status_code != status_codes.ok:
            raise RuntimeError(
                f"API request failed with status code {response.status_code} "
                f"for URL {response.url}: {response.text}"
            )
            # See https://mynotebook.labarchives.com/share/LabArchives%2520API/NDEuNnwyNy8zMi9UcmVlTm9kZS83NDE1Mjk1NTJ8MTA1LjY= [ELN Error Codes]

    def stream_api_get(
        self, api_method_uri: str | Sequence[str], **kwargs: Any
    ) -> Generator[bytes, None, Response]:
        """
        Makes a GET request to the LabArchives API and returns the response as a byte stream.

        This is useful for downloading large files or when the response content
        needs to be processed incrementally.

        :param api_method_uri: The API method URI (e.g., "get_file_attachment").
                               Can be a string or a sequence of strings representing path segments.
        :param kwargs: Additional query parameters to pass to the API method.
        :yields: Chunks of bytes from the API response.
        :returns: The full requests.Response object after the stream has been consumed.
        :raises RuntimeError: If the API request fails.
        """
        with self.session.get(
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
        """
        Makes a POST request to the LabArchives API and returns the response as a byte stream.

        This is useful for uploading large files or when the response content
        needs to be processed incrementally.

        :param api_method_uri: The API method URI (e.g., "upload_file_attachment").
                               Can be a string or a sequence of strings representing path segments.
        :param body: The request body, which can be a mapping of form data or a file-like object.
        :param kwargs: Additional query parameters to pass to the API method.
        :yields: Chunks of bytes from the API response.
        :returns: The full requests.Response object after the stream has been consumed.
        :raises RuntimeError: If the API request fails.
        """
        with self.session.post(
            self.construct_url(api_method_uri, query=kwargs), data=body, stream=True
        ) as request:
            Client._handle_request_status(request)

            for chunk in request.iter_content(1024 * 1024):
                yield chunk

            return request

    def raw_api_get(
        self, api_method_uri: str | Sequence[str], **kwargs: Any
    ) -> Response:
        """
        Makes a GET request to the LabArchives API and returns the raw requests.Response object.

        This method is suitable for API calls where the full HTTP response,
        including headers and status code, is needed, and the content is not
        expected to be streamed.

        :param api_method_uri: The API method URI (e.g., "get_entry_data").
                               Can be a string or a sequence of strings representing path segments.
        :param kwargs: Additional query parameters to pass to the API method.
        :returns: The requests.Response object containing the API response.
        :raises RuntimeError: If the API request fails.
        """
        request = self.session.get(self.construct_url(api_method_uri, query=kwargs))
        Client._handle_request_status(request)

        return request

    def raw_api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ) -> Response:
        """
        Makes a POST request to the LabArchives API and returns the raw requests.Response object.

        This method is suitable for API calls where the full HTTP response,
        including headers and status code, is needed, and the content is not
        expected to be streamed.

        :param api_method_uri: The API method URI (e.g., "create_entry").
                               Can be a string or a sequence of strings representing path segments.
        :param body: The request body, which can be a mapping of form data or a file-like object.
        :param kwargs: Additional query parameters to pass to the API method.
        :returns: The requests.Response object containing the API response.
        :raises RuntimeError: If the API request fails.
        """
        request = self.session.post(
            self.construct_url(api_method_uri, query=kwargs), data=body
        )
        Client._handle_request_status(request)

        return request

    def api_get(self, api_method_uri: str | Sequence[str], **kwargs: Any) -> Element:
        """
        Makes a GET request to the LabArchives API and parses the XML response into an lxml Element.

        This is the primary method for retrieving structured data from the API.

        :param api_method_uri: The API method URI (e.g., "get_notebook_info").
                               Can be a string or a sequence of strings representing path segments.
        :param kwargs: Additional query parameters to pass to the API method.
        :returns: An lxml Element representing the root of the XML response.
        :raises RuntimeError: If the API request fails or the response is not valid XML.
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
        """
        Makes a POST request to the LabArchives API and parses the XML response into an lxml Element.

        This is the primary method for sending data to the API and receiving
        structured XML responses.

        :param api_method_uri: The API method URI (e.g., "create_entry").
                               Can be a string or a sequence of strings representing path segments.
        :param body: The request body, which can be a mapping of form data or a file-like object.
        :param kwargs: Additional query parameters to pass to the API method.
        :returns: An lxml Element representing the root of the XML response.
        :raises RuntimeError: If the API request fails or the response is not valid XML.
        """

        return fromstring(
            bytes(
                self.raw_api_post(api_method_uri, body, **kwargs).text, encoding="utf-8"
            )
        )

    def default_authenticate(self) -> User:
        """
        Authenticates a user using a default browser (Chrome, Firefox, or Edge)
        and a local HTTP server to capture the authentication code.

        This method opens a browser window, directs the user to the LabArchives
        authentication page, and then listens on `http://localhost:8089/` for
        the redirect containing the authorization code. If no compatible browser
        is detected, it falls back to printing the authentication URL to the terminal,
        requiring the user to manually open it.

        .. note::
           This method requires the ``selenium`` package for automatic browser control.
           Install it with: ``pip install selenium``

        :returns: A :class:`~labapi.user.User` object representing the authenticated user session.
        :raises ImportError: If selenium is not installed.
        :raises RuntimeError: If authentication fails.
        """
        auth_url = self.generate_auth_url("http://localhost:8089/")

        driver = None
        options = None
        try:
            match default_browser:
                case "chrome":
                    import selenium.webdriver as webdriver

                    options = webdriver.ChromeOptions()
                    driver = webdriver.Chrome(options=options)
                    print("Opening Chrome for authentication...")
                case "firefox":
                    import selenium.webdriver as webdriver

                    options = webdriver.FirefoxOptions()
                    driver = webdriver.Firefox(options=options)
                    print("Opening Firefox for authentication...")
                case "edge":
                    import selenium.webdriver as webdriver

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
                print(
                    "Please complete the authentication in the opened browser window..."
                )

            return self.collect_auth_response()
        except ImportError as e:
            raise ImportError(
                "Selenium is required for automatic browser-based authentication. "
                "Install it with: pip install selenium\n"
                "Alternatively, use manual authentication with LA_AUTH_BROWSER=terminal."
            ) from e
        finally:
            if driver is not None:
                driver.quit()

    def collect_auth_response(self) -> User:
        """
        Launches a local HTTP server to capture the authentication response from LabArchives.

        This server listens on `http://localhost:8089/` for the redirect from
        LabArchives containing the authorization code and user email after
        successful authentication.

        :returns: A :class:`~labapi.user.User` object representing the authenticated user session.
        :raises KeyError: If the authentication code or email is not received.
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
                    auth_info["error"] = query["error"]
                else:
                    self.wfile.write(b"Thanks for Authenticating. Close this Window")
                    auth_info["auth_code"] = query["auth_code"]
                    auth_info["email"] = query["email"]

            @override
            def log_message(self, format: str, *args: Any) -> None:
                pass

        with TCPServer(("127.0.0.1", 8089), AuthRequestHandler) as httpd:
            httpd.handle_request()

        if "error" in auth_info:
            raise RuntimeError(f"Authentication failed: {auth_info['error']}")

        if "auth_code" not in auth_info or "email" not in auth_info:
            raise RuntimeError(
                "Authentication callback did not include both auth_code and email"
            )

        return self.login(auth_info["email"], auth_info["auth_code"])

    def construct_url(
        self,
        api_method_uri: str | Sequence[str],
        query: Mapping[str, Any],
        expires_in: timedelta | datetime | None = None,
        *,
        should_prefix_api: bool = True,
        signature_method: str | None = None,
    ) -> str:
        """
        Constructs a fully qualified and signed URL for a LabArchives API method.

        This method handles the assembly of the base URL, API method path,
        query parameters, and the HMAC-SHA512 signature required by the LabArchives API.

        :param api_method_uri: The API method URI (e.g., "get_notebook_info").
                               Can be a string or a sequence of strings representing path segments.
        :param query: A dictionary of query parameters to include in the URL.
        :param expires_in: The duration for which the URL should be valid. Can be a
                           `timedelta` object or a specific `datetime` object. If None,
                           defaults to 60 seconds from now.
        :param should_prefix_api: If True, ensures the API method path starts with "api/".
                                  Defaults to True.
        :param signature_method: An optional string to use as the API method for
                                 signature generation, overriding `api_method_uri`.
                                 Useful for methods like `api_user_login` where the
                                 actual method name differs from the URI path.
        :returns: The fully constructed and signed URL.
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
        """
        Generates the HMAC-SHA512 signature for a LabArchives API request.

        This private method is used internally by `_sign_url` to create the
        cryptographic signature based on the Access Key ID, API method, and expiry.

        :param api_method: The specific API method name used in the signature calculation.
        :param expiry: The expiration timestamp (in milliseconds since epoch) for the request.
        :returns: The base64-encoded HMAC-SHA512 signature.
        """
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
        """
        Signs a given URL with the HMAC-SHA512 signature and adds necessary query parameters.

        This private method appends the Access Key ID, expiration timestamp, and
        the generated signature to the URL's query string.

        :param url: The unsigned URL to be signed.
        :param api_method: The specific API method name used for signature generation.
        :param expires_in: The duration for which the URL should be valid. Can be a
                           `timedelta` object or a specific `datetime` object. Defaults
                           to 60 seconds from the current time.
        :returns: The fully signed URL.
        """
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
