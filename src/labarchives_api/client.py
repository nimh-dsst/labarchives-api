import base64
import hmac
import logging
import re
import threading
import time
import webbrowser
from hashlib import sha512
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from typing import Any, Union, Literal
from urllib.parse import parse_qs, quote_plus, urlencode, urlparse, urlunparse
from xml.etree import ElementTree as ET

import requests
from requests import Response

from .config import config
from .utils import parse_user_access_info_response


def mask_sensitive_url(
    url: str, sensitive_params: Union[set[str], None] = None
) -> str:
    """
    Masks sensitive parameters in URLs while preserving the URL structure.

    Args:
        url (str): The URL containing sensitive information
        sensitive_params (set): Set of parameter names to mask.
        If None, uses default set

    Returns:
        str: URL with sensitive information masked

    Example:
        >>> url = "https://api.example.com/v1/data?auth_token=12345&user=john"
        >>> mask_sensitive_url(url)
        'https://api.example.com/v1/data?auth_token=********&user=john'
    """
    # Default sensitive parameters to mask
    default_sensitive_params = {
        "auth_token",
        "auth_code",
        "token",
        "api_key",
        "apikey",
        "password",
        "secret",
        "client_secret",
        "access_token",
        "refresh_token",
        "bearer",
        "authorization",
        "api-key",
        "x-api-key",
        "key",
        "login_or_email",
        "email",
        "login",
    }

    sensitive_params = sensitive_params or default_sensitive_params

    try:
        # Parse the URL
        parsed = urlparse(url)

        # Parse query parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Mask sensitive parameters
        for param, values in query_params.items():
            param_lower = param.lower()
            if any(sensitive in param_lower for sensitive in sensitive_params):
                query_params[param] = ["********" for _ in values]

        # Handle Basic Auth in netloc
        netloc = parsed.netloc
        if "@" in netloc:
            # Mask Basic Auth credentials
            netloc = re.sub(r"^.*@", "********@", netloc)

        # Reconstruct the URL with masked parameters
        masked_query: str = urlencode(query_params, doseq=True)
        masked_url: str = urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                masked_query,
                parsed.fragment,
            )
        )

        return masked_url

    except Exception as e:
        # If URL parsing fails, return the original URL with a warning
        print(f"Warning: Failed to mask URL: {str(e)}")
        return url


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler(),
    ],
)

logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


class CallbackHandler(BaseHTTPRequestHandler):
    callback_responses: list[str] = []

    @classmethod
    def clear_responses(cls):
        cls.callback_responses = []

    def do_GET(self):
        # Store the callback response
        CallbackHandler.callback_responses.append(self.path)
        # Send a nice HTML response that explicitly
        # tells the user to close the window
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = """
        <html>
            <body style="
                text-align: center;
                font-family: Arial, sans-serif;
                padding-top: 50px;
            ">
                <h2>Authentication Complete!</h2>
                <p>Please close this window now. Do not refresh this page.</p>
                <script>
                    // Prevent back/forward navigation
                    window.history.pushState(null, '', window.location.href);
                    window.onpopstate = function () {
                        window.history.pushState(
                            null, '', window.location.href
                        );
                    };
                </script>
            </body>
        </html>
        """
        self.wfile.write(html.encode())

    def log_message(
        self, format: str, *args: Union[str, tuple[str, ...]]
    ) -> None:
        pass


def start_callback_server(port: int = 8000) -> HTTPServer:
    server = HTTPServer(("localhost", port), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server


def generate_signature(
    access_key_id: str, api_method: str, expires: int, access_password: str
) -> str:
    signature_base: str = access_key_id + api_method + str(expires)
    signature_bytes: bytes = hmac.new(
        access_password.encode("utf-8"),
        signature_base.encode("utf-8"),
        sha512,
    ).digest()
    signature: str = quote_plus(
        base64.b64encode(signature_bytes).decode("utf-8")
    )
    return signature


class LAClient:
    def __init__(
        self,
        api_url: Union[str, None] = None,
        access_key_id: Union[str, None] = None,
        access_password: Union[str, None] = None,
        cer_filepath: Union[Path, None] = None,
    ) -> None:
        # Load from config if no values are passed
        if api_url is None:
            if isinstance(config.api_url, str):
                self.api_url = config.api_url
            elif config.api_url is None:
                raise ValueError(
                    "api_url was not set in config nor LAClient init!"
                )
            else:
                raise TypeError(
                    f"config.api_url type: {type(config.api_url)}"
                    + ", must be string or None"
                )
        else:
            self.api_url = api_url

        if access_key_id is None:
            if isinstance(config.access_key_id, str):
                self.access_key_id = config.access_key_id
            elif config.access_key_id is None:
                raise ValueError(
                    "access_key_id was not set in config nor LAClient init!"
                )
            else:
                raise TypeError(
                    f"config.access_key_id type: {type(config.access_key_id)}"
                    + ", must be string or None"
                )
        else:
            self.access_key_id = access_key_id

        if access_password is None:
            if isinstance(config.access_password, str):
                self.access_password = config.access_password
            elif config.access_password is None:
                raise ValueError(
                    "access_password was not set in config nor LAClient init!"
                )
            else:
                raise TypeError(
                    "config.access_password"
                    + f" type: {type(config.access_password)}"
                    + ", must be string or None"
                )
        else:
            self.access_password = access_password
        self.cer_filepath = cer_filepath
        self.is_auth: bool = False
        self.email: Union[str, None] = None
        self.uid: Union[str, None] = None

    def generate_login_url(self, redirect_uri: str, expires: int) -> str:
        url_encoded_uri: str = quote_plus(redirect_uri)
        # Generate the signature
        # NOTE: the api_user_login is special as it requires
        # the redict_uri to inputted NOT the string "api_user_login"
        signature: str = generate_signature(
            self.access_key_id,
            redirect_uri,
            expires,
            self.access_password,
        )
        login_url: str = (
            f"{self.api_url}"
            + "/api_user_login"
            + f"?akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&redirect_uri={url_encoded_uri}"
            + f"&sig={signature}"
        )
        return login_url

    def _get_auth_callback(
        self,
    ) -> tuple[Union[str, None], Union[str, None], list[str], Response]:
        # Clear any previous responses
        CallbackHandler.clear_responses()
        server = start_callback_server()
        auth_code: Union[str, None] = None
        email: Union[str, None] = None
        try:
            expires: int = int(time.time()) * 1000
            redirect_uri: str = "http://localhost:8000/callback"
            login_url: str = self.generate_login_url(redirect_uri, expires)
            # Open the browser for user authentication
            print("Opening browser for authentication...")
            webbrowser.open_new(login_url + "&no_cookies=1")
            # Wait for callback (with timeout)
            timeout = (
                time.time() + 300
            )  # 5 minute timeout for user to complete login
            while (
                not CallbackHandler.callback_responses
                and time.time() < timeout
            ):
                time.sleep(0.1)

            if not CallbackHandler.callback_responses:
                raise TimeoutError("Authentication timed out after 5 minutes")

            # Parse the callback parameters
            callback_params_list = [
                parse_qs(urlparse(response).query)
                for response in CallbackHandler.callback_responses
            ]
            for callback_param in callback_params_list:
                if auth_code is None:
                    auth_code = callback_param.get("auth_code", [None])[0]
                if email is None:
                    email = callback_param.get("email", [None])[0]
            # callback_response = CallbackHandler.callback_response
            if (
                isinstance(self.cer_filepath, Path)
                and self.cer_filepath.exists()
            ):
                response: Response = requests.get(
                    login_url, verify=str(self.cer_filepath)
                )
            else:
                response = requests.get(login_url)
            server.shutdown()
            server.server_close()
            CallbackHandler.clear_responses()
            return (
                auth_code,
                email,
                CallbackHandler.callback_responses,
                response,
            )

        finally:
            # Always shut down the server and clear responses
            server.shutdown()
            server.server_close()
            CallbackHandler.clear_responses()

    def login(
        self,
        auth_code: Union[str, None] = None,
        email: Union[str, None] = None,
    ) -> Response:
        if auth_code is None and email is None:
            callbacks: list[str]
            auth_response: Union[Response, str]
            auth_code, email, callbacks, auth_response = (
                self._get_auth_callback()
            )
        elif isinstance(auth_code, str) and isinstance(email, str):
            callbacks = ["streamlit-based login"]
            auth_response = "streamlit-based login"
        else:
            raise ValueError("Invalid auth_code or email")
        if isinstance(auth_code, str) and isinstance(email, str):
            masked_callbacks: list[str] = [
                mask_sensitive_url(callback) for callback in callbacks
            ]
            logger.debug(f"auth_callbacks: {masked_callbacks}")
            logger.debug(f"auth_response: {auth_response}")
            expires: int = int(time.time()) * 1000
            sig: str = generate_signature(
                self.access_key_id,
                "user_access_info",
                expires,
                self.access_password,
            )
            url: str = (
                self.api_url
                + "/api/users/user_access_info"
                + f"?login_or_email={quote_plus(email)}"
                + f"&password={quote_plus(auth_code)}"
                + f"&akid={self.access_key_id}"
                + f"&expires={expires}"
                + f"&sig={sig}"
            )
            if self.cer_filepath is not None:
                response: Response = requests.get(
                    url, verify=str(self.cer_filepath)
                )
            else:
                response = requests.get(url)
            ua_info: dict[str, Any] = parse_user_access_info_response(
                response=response
            )
            self.ua_info = ua_info
            self.is_auth = True
            self.auth_code = auth_code
            self.email = email
            return response
        else:
            raise ValueError("No auth_code or email returned from get_auth")

    def get_dir_nodes(
        self,
        nbid: str,
        tree_id: str = "0",
        tree_name: str = "root",
        parent_tree_name: str = "",
    ) -> list[ET.Element]:
        """
        Get nodes in the tree of a given level. Not recursive.
        """
        if not self.is_auth or not isinstance(self.email, str):
            raise ValueError("Client is not authenticated")
        all_dir_nodes: list[ET.Element] = []
        full_path: str = (
            parent_tree_name + "/" + tree_name
            if parent_tree_name
            else tree_name
        )
        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "get_tree_level",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/tree_tools/get_tree_level"
            + f"?uid={self.ua_info['id']}"
            + f"&nbid={nbid}"
            + f"&parent_tree_id={tree_id}"
            + f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )
        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        tree: ET.ElementTree = ET.parse(BytesIO(response.content))
        root: ET.Element = tree.getroot()
        nodes: list[ET.Element] = root.findall(".//level-node")
        for node in nodes:
            node_tree_id: ET.Element | None = node.find("tree-id")
            if isinstance(node_tree_id, ET.Element):
                node_tree_id_text: str | None = node_tree_id.text
                if node_tree_id_text is None:
                    raise ValueError("Node tree_id has no text!")
            else:
                raise ValueError("Node is missing tree-id element")
            display_name: ET.Element | None = node.find("display-text")
            is_page: ET.Element | None = node.find("is-page")
            if isinstance(is_page, ET.Element):
                is_page_text: str | None = is_page.text
                if is_page_text is None:
                    raise ValueError("Node is-page element text is missing!")
            else:
                raise ValueError("Node is missing is-page element!")
            if isinstance(display_name, ET.Element):
                display_name_text: str | None = display_name.text
                if display_name_text:
                    if is_page_text == "false":
                        node.set(
                            "full_path", full_path + "/" + display_name_text
                        )
                        all_dir_nodes.append(node)
                    elif is_page_text == "true":
                        pass
                    else:
                        raise ValueError(
                            f"Node: {display_name_text} has is-page"
                            + f" value of {is_page_text}"
                        )
            else:
                raise ValueError("Node is missing display text!")
        return all_dir_nodes

    def get_all_pages(
        self,
        nbid: str,
        tree_id: str = "0",
        tree_name: str = "root",
        parent_tree_name: str = "",
    ) -> list[ET.Element]:
        """
        Get all pages in the tree recursively.
        """
        if not self.is_auth or not isinstance(self.email, str):
            raise ValueError("Client is not authenticated")
        all_pages: list[ET.Element] = []
        full_path: str = (
            parent_tree_name + "/" + tree_name
            if parent_tree_name
            else tree_name
        )
        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "get_tree_level",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/tree_tools/get_tree_level"
            + f"?uid={self.ua_info['id']}"
            + f"&nbid={nbid}"
            + f"&parent_tree_id={tree_id}"
            + f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )
        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        tree: ET.ElementTree = ET.parse(BytesIO(response.content))
        root: ET.Element = tree.getroot()
        nodes: list[ET.Element] = root.findall(".//level-node")
        for node in nodes:
            node_tree_id: ET.Element | None = node.find("tree-id")
            if isinstance(node_tree_id, ET.Element):
                node_tree_id_text: str | None = node_tree_id.text
                if node_tree_id_text is None:
                    raise ValueError("Node tree_id has no text!")
            else:
                raise ValueError("Node is missing tree-id element")
            display_name: ET.Element | None = node.find("display-text")
            is_page: ET.Element | None = node.find("is-page")
            if isinstance(is_page, ET.Element):
                is_page_text: str | None = is_page.text
                if is_page_text is None:
                    raise ValueError("Node is-page element text is missing!")
            else:
                raise ValueError("Node is missing is-page element!")
            if isinstance(display_name, ET.Element):
                display_name_text: str | None = display_name.text
                if display_name_text:
                    if is_page_text == "true":
                        node.set(
                            "full_path", full_path + "/" + display_name_text
                        )
                        all_pages.append(node)
                    elif is_page_text == "false":
                        all_pages.extend(
                            self.get_all_pages(  # type: ignore
                                nbid,
                                node_tree_id_text,
                                display_name_text,
                                full_path,
                            )
                        )
                        pass
                    else:
                        raise ValueError(
                            f"Node: {display_name_text} has is-page"
                            + f" value of {is_page_text}"
                        )
            else:
                raise ValueError("Node is missing display text!")
        return all_pages

    def get_entry_data(self, nbid: str, page_tree_id: str) -> Response:
        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "get_entries_for_page",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/tree_tools/get_entries_for_page"
            + f"?uid={self.ua_info['id']}"
            + f"&page_tree_id={page_tree_id}"
            + "&entry_data=true"
            + f"&nbid={nbid}"
            + f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )
        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        return response

    def get_node_data(self, nbid: str, tree_id: str) -> Response:
        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "get_node",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/tree_tools/get_node"
            + f"?uid={self.ua_info['id']}"
            + f"&nbid={nbid}"
            + f"&tree_id={tree_id}"
            + f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )
        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        return response

    def insert_node(
        self,
        nbid: str,
        parent_tree_id: str,
        display_text: str,
        is_folder: Literal["true", "false"],
    ) -> Response:
        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "insert_node",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/tree_tools/insert_node"
            + f"?uid={self.ua_info['id']}"
            + f"&nbid={nbid}"
            + f"&parent_tree_id={parent_tree_id}"
            + f"&display_text={display_text}"
            + f"&is_folder={is_folder}"
            + f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )
        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        return response

    def add_attachment(
        self,
        filepath: Union[str, Path],
        filename: Union[str, None] = None,
        caption: Union[str, None] = None,
        nbid: Union[str, None] = None,
        pid: Union[str, None] = None,
        change_description: Union[str, None] = None,
        client_ip: Union[str, None] = None,
    ) -> Response:
        """
        Upload a new attachment to the notebook.

        Args:
            filepath: Path to the file to upload
            filename: Optional name for the file (defaults to filepath's name)
            caption: Optional caption for the entry
            nbid: Optional notebook ID to add the entry to
            pid: Optional page ID within the notebook
            change_description: Optional description of changes
            client_ip: Optional IP address of the client

        Returns:
            Response object containing the server's response

        Raises:
            ValueError: If client is not authenticated or file doesn't exist
            FileNotFoundError: If the specified file cannot be found
        """
        if not self.is_auth:
            raise ValueError("Client is not authenticated")

        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        # Use provided filename or get from filepath
        filename = filename or filepath.name

        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "add_attachment",
            expires,
            self.access_password,
        )

        url: str = (
            f"{self.api_url}/api/entries/add_attachment"
            f"?uid={self.ua_info['id']}"
            f"&filename={quote_plus(filename)}"
            f"&akid={self.access_key_id}"
            f"&expires={expires}"
            f"&sig={sig}"
        )

        # Add optional parameters if provided
        if caption:
            url += f"&caption={quote_plus(caption)}"
        if nbid:
            url += f"&nbid={nbid}"
        if pid:
            url += f"&pid={pid}"
        if change_description:
            url += f"&change_description={quote_plus(change_description)}"
        if client_ip:
            url += f"&client_ip={quote_plus(client_ip)}"

        # Read file in binary mode
        with open(filepath, "rb") as file:
            if self.cer_filepath is not None:
                response: Response = requests.post(
                    url,
                    data=file,
                    headers={"Content-Type": "application/octet-stream"},
                    verify=str(self.cer_filepath),
                )
            else:
                response = requests.post(
                    url,
                    data=file,
                    headers={"Content-Type": "application/octet-stream"},
                )

        return response

    def get_attachment_last_uploaded_time(self, eid: str) -> Response:
        """
        Get the date and time that the specified attachment was last uploaded.

        Args:
            eid (str): ID of the entry/attachment to check

        Returns:
            Response: Server response containing the last upload time

        Raises:
            ValueError: If client is not authenticated
        """
        if not self.is_auth:
            raise ValueError("Client is not authenticated")

        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "attachment_last_uploaded_at",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/entries/attachment_last_uploaded_at"
            + f"?uid={self.ua_info['id']}"
            + f"&eid={eid}"
            + f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )

        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        return response

    def get_entries_for_page(
        self,
        nbid: str,
        page_tree_id: str,
        entry_data: bool = False,
        comment_data: bool = False,
    ) -> Response:
        """
        Get a list of Entries that reside on a specific page.

        Args:
            nbid (str): Notebook ID whose tree is to be traversed
            page_tree_id (str): ID of the page of interest
            entry_data (bool, optional): Include entry data in response.
                Defaults to False.
            comment_data (bool, optional): Include comment data in response.
                Defaults to False.

        Returns:
            Response: Server response containing the entries for the
            specified page

        Raises:
            ValueError: If client is not authenticated
        """
        if not self.is_auth:
            raise ValueError("Client is not authenticated")

        expires: int = int(time.time()) * 1000
        sig: str = generate_signature(
            self.access_key_id,
            "get_entries_for_page",
            expires,
            self.access_password,
        )
        url: str = (
            self.api_url
            + "/api/tree_tools/get_entries_for_page"
            + f"?uid={self.ua_info['id']}"
            + f"&page_tree_id={page_tree_id}"
            + f"&nbid={nbid}"
        )

        if entry_data:
            url += "&entry_data=true"
        if comment_data:
            url += "&comment_data=true"

        url += (
            f"&akid={self.access_key_id}"
            + f"&expires={expires}"
            + f"&sig={sig}"
        )

        if self.cer_filepath is not None:
            response: Response = requests.get(
                url, verify=str(self.cer_filepath)
            )
        else:
            response = requests.get(url)
        return response
