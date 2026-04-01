"""Unit tests for Client class."""

from __future__ import annotations

import warnings
from datetime import datetime, timedelta
from os import getenv
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import parse_qsl, urlsplit

import pytest
from lxml.etree import XMLSyntaxError
from requests import Response

from labapi import Client, User
from labapi.exceptions import ApiError, AuthenticationError


def make_response(
    status_code: int,
    body: str,
    url: str = "https://api.test.com/endpoint",
) -> Response:
    """Build a concrete requests.Response object for unit tests."""
    response = Response()
    response.status_code = status_code
    response.url = url
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    return response


class TestClientUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_client_signature_deterministic(self):
        """Test Client._signature generates deterministic signature."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        sig1 = client._signature("test_method", 1234567890000)
        sig2 = client._signature("test_method", 1234567890000)

        assert isinstance(sig1, str)
        assert len(sig1) > 0
        assert sig1 == sig2

    def test_client_signature_different_inputs(self):
        """Test Client._signature produces different signatures for different inputs."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        sig1 = client._signature("method1", 1234567890000)
        sig2 = client._signature("method2", 1234567890000)
        sig3 = client._signature("method1", 9999999999999)

        assert sig1 != sig2
        assert sig1 != sig3

    def test_client_sign_url_adds_parameters(self):
        """Test Client._sign_url adds required query parameters."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        url = "https://api.test.com/api/test_endpoint?param=value"
        signed_url = client._sign_url(url, "test_endpoint", timedelta(seconds=30))

        assert "akid=test_akid" in signed_url
        assert "expires=" in signed_url
        assert "sig=" in signed_url
        assert "param=value" in signed_url

    def test_client_sign_url_with_datetime(self):
        """Test Client._sign_url with datetime parameter."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        url = "https://api.test.com/api/test_endpoint"
        expiry_dt = datetime.fromtimestamp(1234567890)
        signed_url = client._sign_url(url, "test_endpoint", expiry_dt)

        assert "expires=1234567890000" in signed_url

    def test_client_construct_url_simple(self):
        """Test Client.construct_url with simple string API method."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        url = client.construct_url("users/get_info", {"uid": "123"}, expires_in=None)

        assert "api.test.com/api/users/get_info" in url
        assert "uid=123" in url
        assert "akid=test_akid" in url

    def test_client_construct_url_with_sequence(self):
        """Test Client.construct_url with sequence of path segments."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        url = client.construct_url(
            ["users", "get_info"], {"uid": "123"}, expires_in=None
        )

        assert "api.test.com/api/users/get_info" in url

    def test_client_construct_url_no_prefix(self):
        """Test Client.construct_url with should_prefix_api=False."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        url = client.construct_url(
            "user_login",
            {"redirect": "http://localhost"},
            expires_in=None,
            should_prefix_api=False,
        )

        assert "/api/" not in url
        assert "/user_login" in url

    def test_client_construct_url_custom_signature(self):
        """Test Client.construct_url with custom signature_method."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        url = client.construct_url(
            "api_user_login",
            {"redirect": "http://localhost"},
            expires_in=None,
            should_prefix_api=False,
            signature_method="http://localhost",
        )

        assert "/api_user_login" in url
        assert "akid=test_akid" in url

    @pytest.mark.parametrize(
        ("api_method_uri", "kwargs"),
        [
            ("", {}),
            ("/", {}),
            (["", "   "], {}),
            ("api", {"should_prefix_api": False}),
        ],
    )
    def test_client_construct_url_rejects_empty_normalized_paths(
        self,
        api_method_uri: str | list[str],
        kwargs: dict[str, bool],
    ):
        """Test construct_url rejects paths that normalize to no segments."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        with pytest.raises(
            ValueError,
            match="api_method_uri must contain at least one non-empty path segment",
        ):
            client.construct_url(api_method_uri, {"uid": "123"}, **kwargs)

    def test_client_generate_auth_url(self):
        """Test Client.generate_auth_url generates correct authentication URL."""
        client = Client("https://api.test.com", "test_akid", "test_password")

        redirect_url = "http://localhost:8089/"
        auth_url = client.generate_auth_url(redirect_url)

        assert "api.test.com" in auth_url
        assert "api_user_login" in auth_url
        # redirect_uri is URL-encoded in the query string
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8089%2F" in auth_url
        assert "akid=test_akid" in auth_url

    def test_client_generate_auth_url_uses_longer_expiry(self):
        """Test auth URLs use a longer auth-specific expiration window."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        fixed_now = datetime(2026, 4, 1, 12, 0, 0)

        with patch("labapi.client.datetime") as mock_datetime:
            mock_datetime.now.return_value = fixed_now
            auth_url = client.generate_auth_url("http://localhost:8089/")

        expires = dict(parse_qsl(urlsplit(auth_url).query))["expires"]
        assert int(expires) == round(
            (fixed_now + timedelta(minutes=5)).timestamp() * 1000
        )

    def test_client_construct_url_defaults_to_sixty_second_expiry(self):
        """Test ordinary signed URLs still use the default 60 second TTL."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        fixed_now = datetime(2026, 4, 1, 12, 0, 0)

        with patch("labapi.client.datetime") as mock_datetime:
            mock_datetime.now.return_value = fixed_now
            signed_url = client.construct_url("users/get_info", {"uid": "123"})

        expires = dict(parse_qsl(urlsplit(signed_url).query))["expires"]
        assert int(expires) == round(
            (fixed_now + timedelta(seconds=60)).timestamp() * 1000
        )

    def test_client_api_get_parses_raw_response_bytes(self):
        """Test Client.api_get parses response.content rather than re-encoded text."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = Response()
        response.status_code = 200
        response.encoding = "iso-8859-1"
        response._content = (
            b'<?xml version="1.0" encoding="ISO-8859-1"?>'
            b"<root><value>caf\xe9</value></root>"
        )
        client.raw_api_get = Mock(return_value=response)  # pyright: ignore[reportAttributeAccessIssue]

        result = client.api_get("test_endpoint")

        assert result.findtext("./value") == "café"

    def test_client_api_post_parses_raw_response_bytes(self):
        """Test Client.api_post parses response.content rather than re-encoded text."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = Response()
        response.status_code = 200
        response.encoding = "iso-8859-1"
        response._content = (
            b'<?xml version="1.0" encoding="ISO-8859-1"?>'
            b"<root><value>caf\xe9</value></root>"
        )
        client.raw_api_post = Mock(return_value=response)  # pyright: ignore[reportAttributeAccessIssue]

        result = client.api_post("test_endpoint", {"data": "test"})

        assert result.findtext("./value") == "café"

    def test_client_handle_request_status_success(self):
        """Test Client._handle_request_status with successful response."""
        response = Mock(spec=Response)
        response.status_code = 200

        Client._handle_request_status(response)

    def test_client_close_closes_session(self):
        """Test Client.close closes the underlying requests session."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.close = Mock()

        client.close()

        client.session.close.assert_called_once_with()

    def test_client_context_manager_closes_session(self):
        """Test context-manager exit closes session and marks client unusable."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.close = Mock()
        client.session.get = Mock()

        with client as managed:
            assert managed is client

        client.session.close.assert_called_once_with()

        with pytest.raises(RuntimeError, match="Client session is closed"):
            client.raw_api_get("users/get_info")

        client.session.get.assert_not_called()

    def test_client_del_closes_session(self):
        """Test Client.__del__ performs best-effort session cleanup."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.close = Mock()

        client.__del__()

        client.session.close.assert_called_once_with()

    def test_client_rejects_requests_after_close(self):
        """Test closed clients reject further request calls."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.get = Mock()

        client.close()

        with pytest.raises(RuntimeError, match="Client session is closed"):
            client.raw_api_get("users/get_info")

        client.session.get.assert_not_called()

    def test_client_handle_request_status_failure(self):
        """Test Client._handle_request_status with failed response."""
        response = Mock(spec=Response)
        response.status_code = 404
        response.url = "https://api.test.com/endpoint"
        response.text = "Not Found"

        with pytest.raises(ApiError, match="API request failed with status code 404"):
            Client._handle_request_status(response)

    def test_raw_api_get_returns_response(self):
        """Test raw_api_get returns the raw response and calls session.get directly."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = make_response(200, "<users><id>123</id></users>")
        client.session.get = Mock(return_value=response)

        result = client.raw_api_get("users/get_info", uid="123")

        assert result is response
        called_url = client.session.get.call_args.args[0]
        assert "users/get_info" in called_url
        assert "uid=123" in called_url

    def test_raw_api_post_returns_response(self):
        """Test raw_api_post returns the raw response and passes the request body."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = make_response(200, "<entries><entry><eid>1</eid></entry></entries>")
        client.session.post = Mock(return_value=response)
        body = {"entry_data": "<p>Hello</p>"}

        result = client.raw_api_post("entries/add_entry", body, pid="123")

        assert result is response
        called_url = client.session.post.call_args.args[0]
        assert "entries/add_entry" in called_url
        assert client.session.post.call_args.kwargs["data"] == body

    def test_raw_api_get_raises_api_error_from_xml_error_body(self):
        """Test raw_api_get surfaces LabArchives XML error payloads."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.get = Mock(
            return_value=make_response(
                500,
                (
                    "<error>"
                    "<error-code>4999</error-code>"
                    "<error-description>Unknown Error</error-description>"
                    "</error>"
                ),
            )
        )

        with pytest.raises(ApiError, match=r"\[4999\] Unknown Error"):
            client.raw_api_get("users/get_info")

    def test_raw_api_get_raises_authentication_error_for_auth_failures(self):
        """Test raw_api_get maps auth-related XML errors to AuthenticationError."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.get = Mock(
            return_value=make_response(
                401,
                (
                    "<error>"
                    "<error-code>4533</error-code>"
                    "<error-description>session timed out</error-description>"
                    "</error>"
                ),
            )
        )

        with pytest.raises(AuthenticationError, match=r"\[4533\] session timed out"):
            client.raw_api_get("users/get_info")

    def test_api_get_parses_xml_response(self):
        """Test api_get parses successful XML responses into Elements."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.get = Mock(
            return_value=make_response(200, "<users><id>123</id></users>")
        )

        tree = client.api_get("users/get_info")

        assert tree.tag == "users"
        assert tree.findtext("./id") == "123"

    def test_api_get_raises_on_malformed_xml(self):
        """Test api_get propagates XML parse failures for malformed responses."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.get = Mock(return_value=make_response(200, "<users>"))

        with pytest.raises(XMLSyntaxError):
            client.api_get("users/get_info")

    def test_api_post_parses_xml_response(self):
        """Test api_post parses successful XML responses into Elements."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.post = Mock(
            return_value=make_response(200, "<entry><eid>123</eid></entry>")
        )

        tree = client.api_post("entries/add_entry", {"entry_data": "<p>Hello</p>"})

        assert tree.tag == "entry"
        assert tree.findtext("./eid") == "123"

    def test_api_post_raises_on_malformed_xml(self):
        """Test api_post propagates XML parse failures for malformed responses."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.session.post = Mock(return_value=make_response(200, "<entry>"))

        with pytest.raises(XMLSyntaxError):
            client.api_post("entries/add_entry", {"entry_data": "<p>Hello</p>"})

    def test_default_authenticate_warns_when_no_browser_detected(
        self, capsys, monkeypatch
    ):
        """Test warning path when no compatible browser is detected."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.collect_auth_response = Mock(return_value=Mock(spec=User))
        monkeypatch.delenv("LA_AUTH_BROWSER", raising=False)

        with patch("labapi.client.default_browser", None):
            with pytest.warns(
                UserWarning,
                match="Automatic browser detection requires the 'builtin-auth' extra",
            ):
                client.default_authenticate()

        captured = capsys.readouterr()
        assert "WARNING: No compatible browser detected" in captured.out
        assert "Open authentication URL in your browser:" in captured.out

    def test_default_authenticate_does_not_warn_when_terminal_is_explicit(
        self, monkeypatch
    ):
        """Test no warning is shown when terminal auth is explicitly configured."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        client.collect_auth_response = Mock(return_value=Mock(spec=User))
        monkeypatch.setenv("LA_AUTH_BROWSER", "terminal")

        with patch("labapi.client.default_browser", None):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                client.default_authenticate()

    def test_default_authenticate_uses_loopback_callback_url(self, monkeypatch):
        """Test interactive auth uses the same loopback callback URL it listens on."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        generate_auth_url = Mock(return_value="https://auth.test/url")
        collect_auth_response = Mock(return_value=Mock(spec=User))
        monkeypatch.setenv("LA_AUTH_BROWSER", "terminal")

        with (
            patch.object(client, "generate_auth_url", generate_auth_url),
            patch.object(client, "collect_auth_response", collect_auth_response),
            patch("labapi.client.default_browser", "terminal"),
        ):
            client.default_authenticate()

        generate_auth_url.assert_called_once_with("http://127.0.0.1:8089/")
        collect_auth_response.assert_called_once_with(port=8089)

    def test_default_authenticate_accepts_custom_callback_port(self, monkeypatch):
        """Test interactive auth uses a caller-provided callback port."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        generate_auth_url = Mock(return_value="https://auth.test/url")
        collect_auth_response = Mock(return_value=Mock(spec=User))
        monkeypatch.setenv("LA_AUTH_BROWSER", "terminal")

        with (
            patch.object(client, "generate_auth_url", generate_auth_url),
            patch.object(client, "collect_auth_response", collect_auth_response),
            patch("labapi.client.default_browser", "terminal"),
        ):
            client.default_authenticate(port=9001)

        generate_auth_url.assert_called_once_with("http://127.0.0.1:9001/")
        collect_auth_response.assert_called_once_with(port=9001)

    def test_collect_auth_response_binds_loopback_callback_listener(self):
        """Test auth callback capture binds the expected loopback listener."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        bind_info: dict[str, tuple[str, int]] = {}

        class StopServer(Exception):
            """Sentinel exception to stop before request handling."""

        class FakeTCPServer:
            def __init__(self, server_address, _handler_cls):
                bind_info["server_address"] = server_address

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

            def handle_request(self):
                raise StopServer()

        with patch("labapi.client.TCPServer", FakeTCPServer):
            with pytest.raises(StopServer):
                client.collect_auth_response()

        assert bind_info["server_address"] == ("127.0.0.1", 8089)

    def test_collect_auth_response_accepts_custom_callback_port(self):
        """Test auth callback capture can bind a caller-provided port."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        bind_info: dict[str, tuple[str, int]] = {}

        class StopServer(Exception):
            """Sentinel exception to stop before request handling."""

        class FakeTCPServer:
            def __init__(self, server_address, _handler_cls):
                bind_info["server_address"] = server_address

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

            def handle_request(self):
                raise StopServer()

        with patch("labapi.client.TCPServer", FakeTCPServer):
            with pytest.raises(StopServer):
                client.collect_auth_response(port=9001)

        assert bind_info["server_address"] == ("127.0.0.1", 9001)

    def test_stream_api_get_yields_chunks_and_returns_response(self):
        """Test stream_api_get yields streamed chunks and returns the response."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = MagicMock(spec=Response)
        response.status_code = 200
        response.headers = {"Content-Type": "application/octet-stream"}
        response.iter_content.return_value = [b"chunk-1", b"chunk-2"]
        client.session.get = Mock(return_value=response)

        stream = client.stream_api_get("attachments/download", eid="123")
        chunks = list(stream)

        assert chunks == [b"chunk-1", b"chunk-2"]
        assert stream.response is response
        assert stream.headers == {"Content-Type": "application/octet-stream"}

    def test_stream_api_get_raises_api_error_before_yielding_chunks(self):
        """Test stream_api_get raises before yielding when the response is not OK."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = MagicMock(spec=Response)
        response.status_code = 404
        response.url = "https://api.test.com/api/attachments/download"
        response.text = "Not Found"
        client.session.get = Mock(return_value=response)

        with pytest.raises(ApiError, match="API request failed with status code 404"):
            client.stream_api_get("attachments/download", eid="123")

        response.iter_content.assert_not_called()
        response.close.assert_called_once()

    def test_stream_api_post_raises_api_error_and_closes_response(self):
        """Test stream_api_post closes failed streamed responses before raising."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = MagicMock(spec=Response)
        response.status_code = 500
        response.url = "https://api.test.com/api/attachments/upload"
        response.text = "Internal Server Error"
        client.session.post = Mock(return_value=response)

        with pytest.raises(ApiError, match="API request failed with status code 500"):
            client.stream_api_post("attachments/upload", {"entry_data": "test"}, eid="1")

        response.iter_content.assert_not_called()
        response.close.assert_called_once()

    def test_stream_api_post_returns_streaming_response(self):
        """Test stream_api_post returns an iterable wrapper with the response."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = MagicMock(spec=Response)
        response.status_code = 200
        response.iter_content.return_value = [b"chunk-1", b"chunk-2"]
        client.session.post = Mock(return_value=response)

        stream = client.stream_api_post(
            "attachments/upload", {"entry_data": "test"}, eid="123"
        )
        chunks = list(stream)

        assert chunks == [b"chunk-1", b"chunk-2"]
        assert stream.response is response

    def test_streaming_response_closes_after_iteration(self):
        """Test StreamingResponse closes the response when iteration completes."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = MagicMock(spec=Response)
        response.status_code = 200
        response.iter_content.return_value = [b"chunk-1"]
        client.session.get = Mock(return_value=response)

        stream = client.stream_api_get("attachments/download", eid="123")
        assert list(stream) == [b"chunk-1"]

        response.close.assert_called_once()

    def test_streaming_response_supports_context_manager(self):
        """Test StreamingResponse can be used as a context manager."""
        client = Client("https://api.test.com", "test_akid", "test_password")
        response = MagicMock(spec=Response)
        response.status_code = 200
        response.iter_content.return_value = [b"chunk-1"]
        client.session.get = Mock(return_value=response)

        with client.stream_api_get("attachments/download", eid="123") as stream:
            assert list(stream) == [b"chunk-1"]
            assert stream.response is response

        # Closing is idempotent even though both iterator and context manager clean up.
        response.close.assert_called_once()

    def test_client_initialization_with_params(self):
        """Test Client initialization stores parameters correctly."""
        client = Client("https://custom.api.com", "my_akid", "my_password")

        assert client._base_url == "https://custom.api.com"
        assert client._akid == "my_akid"

    def test_client_initialization_rejects_non_http_scheme(self):
        """Test Client initialization rejects unsupported base URL schemes."""
        with pytest.raises(AuthenticationError, match="expected a full HTTP\\(S\\) URL"):
            Client("ftp://api.test.com", "test_akid", "test_password")

    def test_client_initialization_rejects_malformed_base_url(self):
        """Test Client initialization rejects malformed base URLs."""
        with pytest.raises(AuthenticationError, match="API_URL/base_url"):
            Client("not-a-url", "test_akid", "test_password")

    def test_client_initialization_from_env_vars(self, monkeypatch):
        """Test Client initialization reads from environment variables."""
        monkeypatch.setenv("ACCESS_KEYID", "test_akid")
        monkeypatch.setenv("ACCESS_PWD", "test_password")
        monkeypatch.delenv("API_URL", raising=False)

        client = Client()

        assert client._akid == "test_akid"
        assert client._base_url == "https://api.labarchives.com"

    @pytest.mark.skipif(
        not getenv("ACCESS_KEYID"), reason="Environment variables not set"
    )
    def test_client_initialization_from_dotenv(self):
        """Test Client initialization falls back to .env file."""
        client = Client()
        assert client._base_url is not None
        assert client._akid is not None


class TestClientIntegration:
    """Integration tests with MockClient and real objects."""

    def test_client_login_creates_user(self, client):
        """Test Client.login creates User with notebooks from API response."""
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <users>
            <fullname>Test User</fullname>
            <id>user_test_id</id>
            <auto-login-allowed type="boolean">false</auto-login-allowed>
            <request></request>
            <notebooks type="array">
                <notebook>
                    <is-default type="boolean">true</is-default>
                    <name>Notebook 1</name>
                    <id>nb1</id>
                </notebook>
            </notebooks>
        </users>
        """

        user = client.login("test@example.com", "authcode123")

        assert isinstance(user, User)
        assert user.id == "user_test_id"
        assert len(user.notebooks) == 1

        api_call = client.api_log
        assert api_call[0] == "users/user_access_info"
        assert api_call[1]["login_or_email"] == "test@example.com"
        assert api_call[1]["password"] == "authcode123"
