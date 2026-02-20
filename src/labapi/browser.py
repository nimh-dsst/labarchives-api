import installed_browsers  # pyright: ignore[reportMissingTypeStubs]
from os import getenv

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

default_browser = "terminal"

# TODO more browsers?
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

    if default_browser == "terminal":
        if len(browsers) > 0:
            browser_name = browsers[0]["name"].lower()

            # BUG: I think we are detected betas and nightlys here which might cause an issue
            # with Selenium if the installed location is wrong
            # TODO: fix with get_details_of() and get the executable path to feed to the driver

            for choice in browser_choices:
                if choice in browser_name:
                    default_browser = choice
                    break
