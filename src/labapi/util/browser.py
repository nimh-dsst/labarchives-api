"""Browser detection helpers for interactive authentication."""

from __future__ import annotations

import os
import warnings
from typing import Literal

_BROWSER_CHOICES = ("chrome", "firefox", "edge")


def _matching_browser_choice(
    browser_name: object,
) -> Literal["chrome", "firefox", "edge"] | None:
    normalized_name = str(browser_name or "").lower()

    for choice in _BROWSER_CHOICES:
        if choice in normalized_name:
            return choice

    return None


def detect_default_browser() -> Literal["chrome", "firefox", "edge", "terminal"]:
    """Resolve the preferred browser for the current auth attempt."""
    raw_env_browser = os.getenv("LA_AUTH_BROWSER", "").strip().lower()

    if raw_env_browser == "terminal":
        return "terminal"

    real_browser = raw_env_browser if raw_env_browser in _BROWSER_CHOICES else None

    if raw_env_browser and real_browser is None:
        warnings.warn(
            f"Unrecognized LA_AUTH_BROWSER value {raw_env_browser!r}; "
            "supported values are chrome, firefox, edge, or terminal. "
            "Falling back to automatic browser detection.",
            stacklevel=2,
        )

    try:
        import installed_browsers  # pyright: ignore[reportMissingImports, reportMissingTypeStubs]
    except ImportError:
        if real_browser is not None or not raw_env_browser:
            warnings.warn(
                "Automatic browser detection requires the optional 'builtin-auth' "
                "dependencies. Install them with: pip install 'labapi[builtin-auth]' "
                "or set LA_AUTH_BROWSER=terminal for manual authentication.",
                stacklevel=2,
            )
        return "terminal"

    try:
        if real_browser is not None:
            if installed_browsers.do_i_have_installed(real_browser):
                return real_browser
            warnings.warn(
                f"Configured LA_AUTH_BROWSER value {real_browser!r} is not installed. "
                "Falling back to automatic browser detection.",
                stacklevel=2,
            )

        detected_browser = _matching_browser_choice(
            installed_browsers.what_is_the_default_browser()
        )
        if detected_browser is not None:
            return detected_browser

        for browser in installed_browsers.browsers():
            detected_browser = _matching_browser_choice(browser.get("name"))
            if detected_browser is not None:
                return detected_browser

        warnings.warn(
            "Automatic browser detection failed: No compatible browser. Falling back to terminal/manual auth.",
            RuntimeWarning,
            stacklevel=2,
        )
    except Exception as exc:
        warnings.warn(
            f"Automatic browser detection failed: {exc}. Falling back to terminal/manual auth.",
            RuntimeWarning,
            stacklevel=2,
        )

    return "terminal"
