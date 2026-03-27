"""Browser Detection Module.

This module attempts to detect an installed web browser (Chrome, Firefox, or Edge)
to be used for OAuth-like authentication flows. It prioritizes a browser specified
via the `LA_AUTH_BROWSER` environment variable, then the system's default browser,
and finally any detected installed browser. If no compatible browser is found,
it defaults to "terminal", indicating that the authentication URL should be
opened manually by the user.

The detected browser is exposed via the `default_browser` module-level variable.
"""

from os import getenv

browser_warning: str | None = None
raw_env_browser = getenv("LA_AUTH_BROWSER", "").strip().lower()

try:
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
except ImportError:
    default_browser = "terminal"
    if raw_env_browser != "terminal":
        browser_warning = (
            "Automatic browser detection requires the optional builtin-auth "
            "dependencies. Install them with "
            "\"uv add labapi --optional builtin-auth\" or "
            "\"pip install 'labapi[builtin-auth]'\"."
        )
