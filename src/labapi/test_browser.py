"""Unit tests for browser detection module."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


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
        # Reload module to trigger detection logic
        if "labapi.browser" in sys.modules:
            del sys.modules["labapi.browser"]
        import labapi.browser

        assert labapi.browser.default_browser == "firefox"


def test_browser_detection_default_system(mock_installed_browsers):
    """Test browser selection based on system default."""
    mock_installed_browsers[
        "what_is_the_default_browser"
    ].return_value = "Google Chrome"

    with patch("os.getenv", return_value=""):
        if "labapi.browser" in sys.modules:
            del sys.modules["labapi.browser"]
        import labapi.browser

        assert labapi.browser.default_browser == "chrome"


def test_browser_detection_fallback_list(mock_installed_browsers):
    """Test fallback to first detected compatible browser."""
    mock_installed_browsers["what_is_the_default_browser"].return_value = None
    mock_installed_browsers["browsers"].return_value = [
        {"name": "Firefox Nightly", "path": "/path/to/firefox"}
    ]

    with patch("os.getenv", return_value=""):
        if "labapi.browser" in sys.modules:
            del sys.modules["labapi.browser"]
        import labapi.browser

        assert labapi.browser.default_browser == "firefox"


def test_browser_detection_terminal_fallback(mock_installed_browsers):
    """Test fallback to 'terminal' when no compatible browser is found."""
    mock_installed_browsers["what_is_the_default_browser"].return_value = None
    mock_installed_browsers["browsers"].return_value = []

    with patch("os.getenv", return_value=""):
        if "labapi.browser" in sys.modules:
            del sys.modules["labapi.browser"]
        import labapi.browser

        assert labapi.browser.default_browser == "terminal"


def test_browser_detection_import_error():
    """Test fallback to 'terminal' when installed_browsers cannot be imported."""
    with patch.dict("sys.modules", {"installed_browsers": None}):
        if "labapi.browser" in sys.modules:
            del sys.modules["labapi.browser"]
        import labapi.browser

        assert labapi.browser.default_browser == "terminal"
