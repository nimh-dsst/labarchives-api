"""Browser Detection Module.

This module attempts to detect an installed web browser (Chrome, Firefox, or Edge)
to be used for OAuth-like authentication flows. It prioritizes a browser specified
via the `LA_AUTH_BROWSER` environment variable, then the system's default browser,
and finally any detected installed browser. If no compatible browser is found,
it keeps a ``None`` sentinel so auth code can emit a warning before falling
back to terminal URL output.

The detected browser is exposed via the `default_browser` module-level variable.
"""

import warnings

try:
    from os import getenv

    import installed_browsers  # pyright: ignore[reportMissingTypeStubs]

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
    raw_env_browser = getenv("LA_AUTH_BROWSER", "").strip().lower()

    default_browser: str | None = None

    browser_choices = ["chrome", "firefox", "edge"]  # priority in order of order

    if raw_env_browser == "terminal":
        default_browser = "terminal"
    elif raw_env_browser in ("chrome", "firefox", "edge"):
        if installed_browsers.do_i_have_installed(raw_env_browser):
            default_browser = raw_env_browser
    else:
        if raw_default_browser:
            raw_default_browser = raw_default_browser.lower()

            for choice in browser_choices:
                if choice in raw_default_browser:
                    default_browser = choice
                    break

        if default_browser is None:
            if len(browsers) > 0:
                browser_name = browsers[0]["name"].lower()

                for choice in browser_choices:
                    if choice in browser_name:
                        default_browser = choice
                        break
except ImportError:
    default_browser = None
except Exception as exc:
    warnings.warn(
        f"Automatic browser detection failed: {exc}. Falling back to terminal/manual auth.",
        RuntimeWarning,
        stacklevel=2,
    )
    default_browser = None
