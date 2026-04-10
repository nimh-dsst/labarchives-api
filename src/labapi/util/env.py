"""Helpers for reading environment variables with optional `.env` loading."""

import contextlib
from os import getenv as _getenv

_loaded = False


def getenv[T](key: str, default: T = None, *args, **kwargs) -> str | T:
    """Return an environment variable, loading ``.env`` on first use.

    If ``python-dotenv`` is installed, this wrapper calls ``load_dotenv()``
    the first time it is used so values from a local ``.env`` file are
    available through :func:`os.getenv`.

    :param key: The environment variable name to look up.
    :param default: The value to return when ``key`` is not set.
    :returns: The environment variable value, or ``default`` if unset.
    """
    global _loaded

    if not _loaded:
        with contextlib.suppress(ImportError):
            from dotenv import load_dotenv

            load_dotenv()
            _loaded = True

    return _getenv(key, default, *args, **kwargs)
