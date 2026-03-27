"""Browser Detection Module.

This module attempts to detect an installed web browser (Chrome, Firefox, or Edge)
to be used for OAuth-like authentication flows. It prioritizes a browser specified
via the `LA_AUTH_BROWSER` environment variable, then the system's default browser,
and finally any detected installed browser. If no compatible browser is found,
it defaults to "terminal", indicating that the authentication URL should be
opened manually by the user.

The detected browser is resolved lazily via :func:`get_default_browser`.
"""

from __future__ import annotations

import os

_default_browser: str | None = None


def _detect_browser() -> str:
    try:
        import installed_browsers  # pyright: ignore[reportMissingTypeStubs]
    except ImportError:
        return "terminal"

    browsers = [
        x
        for x in installed_browsers.browsers()
        if (
            "chrome" in x["name"].lower()
            or "firefox" in x["name"].lower()
            or "edge" in x["name"].lower()
        )
    ]
    raw_default_browser = installed_browsers.what_is_the_default_browser()
    raw_env_browser = os.getenv("LA_AUTH_BROWSER", "").strip().lower()

    default_browser = "terminal"
    browser_choices = ["chrome", "firefox", "edge"]  # priority in order of order

    if raw_env_browser in ("chrome", "firefox", "edge", "terminal"):
        if installed_browsers.do_i_have_installed(raw_env_browser):
            default_browser = raw_env_browser
    else:
        if raw_default_browser:
            raw_default_browser = raw_default_browser.lower()

            for choice in browser_choices:
                if choice in raw_default_browser:
                    default_browser = choice
                    break

        # FIXME the way this is written we'll never *NOT* have a compatible 'browser'
        # because `terminal` is registered in default_authenticate as a real value
        # the warning for No compatible browser never triggers

        if default_browser == "terminal":
            if len(browsers) > 0:
                browser_name = browsers[0]["name"].lower()

                for choice in browser_choices:
                    if choice in browser_name:
                        default_browser = choice
                        break

    return default_browser


def get_default_browser() -> str:
    """Detect and cache the preferred authentication browser on first use."""
    global _default_browser

    if _default_browser is None:
        _default_browser = _detect_browser()

    return _default_browser


def __getattr__(name: str) -> str:
    """Preserve the historical module attribute while making detection lazy."""
    if name == "default_browser":
        return get_default_browser()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
