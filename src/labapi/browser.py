"""Browser Detection Module.

This module attempts to detect an installed web browser (Chrome, Firefox, or Edge)
to be used for OAuth-like authentication flows. It prioritizes a browser specified
via the `LA_AUTH_BROWSER` environment variable, then the system's default browser,
and finally any detected installed browser. If no compatible browser is found,
it defaults to "terminal", indicating that the authentication URL should be
opened manually by the user.

The detected browser is exposed via the `default_browser` module-level variable.
"""

try:
    from os import getenv

    import installed_browsers  # pyright: ignore[reportMissingTypeStubs]

    unstable_browser_channels = ("canary", "nightly", "beta", "dev", "unstable")
    browser_choices = ["chrome", "firefox", "edge"]  # priority in order of order

    def is_stable_compatible_browser(name: str) -> bool:
        lowered_name = name.lower()
        return (
            any(choice in lowered_name for choice in browser_choices)
            and not any(channel in lowered_name for channel in unstable_browser_channels)
        )

    browsers = [
        x
        for x in installed_browsers.browsers()
        if is_stable_compatible_browser(x["name"])
    ]
    raw_default_browser = installed_browsers.what_is_the_default_browser()
    raw_env_browser = getenv("LA_AUTH_BROWSER", "").strip().lower()

    default_browser = "terminal"

    if raw_env_browser in ("chrome", "firefox", "edge", "terminal"):
        if installed_browsers.do_i_have_installed(raw_env_browser):
            default_browser = raw_env_browser
    else:
        if raw_default_browser:
            raw_default_browser = raw_default_browser.lower()

            if is_stable_compatible_browser(raw_default_browser):
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
