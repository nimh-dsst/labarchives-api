"""Unit tests for browser detection module."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest


def import_browser_module():
    """Reload the browser module so import-time detection runs again."""
    sys.modules.pop("labapi.browser", None)
    return importlib.import_module("labapi.browser")


@pytest.fixture
def mock_installed_browsers():
    """Fixture to mock the installed_browsers module."""
    mock_module = MagicMock()
    with patch.dict("sys.modules", {"installed_browsers": mock_module}):
        with (
            patch("installed_browsers.browsers") as mock_browsers,
            patch("installed_browsers.what_is_the_default_browser") as mock_default,
            patch("installed_browsers.do_i_have_installed") as mock_have,
        ):
            yield {
                "browsers": mock_browsers,
                "what_is_the_default_browser": mock_default,
                "do_i_have_installed": mock_have,
            }


def test_browser_detection_env_var(mock_installed_browsers):
    """Test browser selection based on LA_AUTH_BROWSER environment variable."""
    mock_installed_browsers["do_i_have_installed"].return_value = True

    with patch("os.getenv", return_value="firefox"):
        browser = import_browser_module()
        assert browser.default_browser == "firefox"


def test_browser_detection_default_system(mock_installed_browsers):
    """Test browser selection based on system default."""
    mock_installed_browsers[
        "what_is_the_default_browser"
    ].return_value = "Google Chrome"

    with patch("os.getenv", return_value=""):
        browser = import_browser_module()
        assert browser.default_browser == "chrome"


def test_browser_detection_fallback_list(mock_installed_browsers):
    """Test fallback to first detected compatible browser."""
    mock_installed_browsers["what_is_the_default_browser"].return_value = None
    mock_installed_browsers["browsers"].return_value = [
        {"name": "Firefox Nightly", "path": "/path/to/firefox"}
    ]

    with patch("os.getenv", return_value=""):
        browser = import_browser_module()
        assert browser.default_browser == "firefox"


def test_browser_detection_terminal_fallback(mock_installed_browsers):
    """Test no-browser sentinel when no compatible browser is found."""
    mock_installed_browsers["what_is_the_default_browser"].return_value = None
    mock_installed_browsers["browsers"].return_value = []

    with patch("os.getenv", return_value=""):
        browser = import_browser_module()
        assert browser.default_browser is None


def test_browser_detection_import_error():
    """Test no-browser sentinel when installed_browsers cannot be imported."""
    with patch.dict("sys.modules", {"installed_browsers": None}):
        browser = import_browser_module()
        assert browser.default_browser is None


def test_browser_detection_runtime_failure_warns(mock_installed_browsers):
    """Test runtime probe failures fall back to manual auth without crashing."""
    mock_installed_browsers["browsers"].side_effect = OSError("registry unavailable")

    with patch("os.getenv", return_value=""), pytest.warns(
        RuntimeWarning, match="Automatic browser detection failed"
    ):
        browser = import_browser_module()

    assert browser.default_browser is None


def test_browser_detection_explicit_terminal_override(mock_installed_browsers):
    """Test terminal override from LA_AUTH_BROWSER."""
    with patch("os.getenv", return_value="terminal"):
        browser = import_browser_module()
        assert browser.default_browser == "terminal"
