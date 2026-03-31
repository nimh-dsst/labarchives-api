class LabArchivesError(Exception):
    """Base for all labarchives-api exceptions."""


class AuthenticationError(LabArchivesError):
    """Missing credentials or failed authentication flow.

    ``error_code`` is set when the error originates from the LabArchives API
    (e.g. 4506 invalid akid, 4514 bad login, 4520 bad signature, 4533 session
    timeout).  It is ``None`` for locally-detected credential errors.
    """

    def __init__(self, message: str, error_code: int | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class ApiError(LabArchivesError):
    """LabArchives API returned an error or unexpected response.

    ``error_code`` is the numeric code from the API ``<error-code>`` element,
    or ``None`` if the error was detected before parsing the response body.
    """

    def __init__(self, message: str, error_code: int | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class NodeExistsError(LabArchivesError):
    """A tree node with the given name already exists (raised by InsertBehavior.Raise)."""


class PathError(LabArchivesError):
    """Path construction or resolution failed."""

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        parent: str | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.parent = parent


class TraversalError(LabArchivesError):
    """Tree traversal failed."""

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        segment: str | None = None,
        parent: str | None = None,
        available_children: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.segment = segment
        self.parent = parent
        self.available_children = available_children


class ExtractionError(LabArchivesError, ValueError):
    """Structured parse/extraction failure while reading XML data."""


class TreeChildParseError(ExtractionError):
    """A tree child node could not be parsed from a tree-level response."""
