"""Unit tests for browser detection module."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


def import_browser_module():
    """Import the browser module fresh for each test."""
    sys.modules.pop("labapi.browser", None)
    import labapi.browser

    return labapi.browser


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

    browser = import_browser_module()

    with patch("os.getenv", return_value="firefox"):
        assert browser.get_default_browser() == "firefox"


def test_browser_detection_default_system(mock_installed_browsers):
    """Test browser selection based on system default."""
    mock_installed_browsers[
        "what_is_the_default_browser"
    ].return_value = "Google Chrome"

    browser = import_browser_module()

    with patch("os.getenv", return_value=""):
        assert browser.get_default_browser() == "chrome"


def test_browser_detection_fallback_list(mock_installed_browsers):
    """Test fallback to first detected compatible browser."""
    mock_installed_browsers["what_is_the_default_browser"].return_value = None
    mock_installed_browsers["browsers"].return_value = [
        {"name": "Firefox Nightly", "path": "/path/to/firefox"}
    ]

    browser = import_browser_module()

    with patch("os.getenv", return_value=""):
        assert browser.default_browser == "firefox"


def test_browser_detection_terminal_fallback(mock_installed_browsers):
    """Test fallback to 'terminal' when no compatible browser is found."""
    mock_installed_browsers["what_is_the_default_browser"].return_value = None
    mock_installed_browsers["browsers"].return_value = []

    browser = import_browser_module()

    with patch("os.getenv", return_value=""):
        assert browser.default_browser == "terminal"


def test_browser_detection_import_is_lazy(mock_installed_browsers):
    """Test import alone does not inspect browsers or environment variables."""
    import_browser_module()

    mock_installed_browsers["browsers"].assert_not_called()
    mock_installed_browsers["what_is_the_default_browser"].assert_not_called()
    mock_installed_browsers["do_i_have_installed"].assert_not_called()


def test_browser_detection_import_error():
    """Test fallback to 'terminal' when installed_browsers cannot be imported."""
    with patch.dict("sys.modules", {"installed_browsers": None}):
        browser = import_browser_module()

        assert browser.default_browser == "terminal"
