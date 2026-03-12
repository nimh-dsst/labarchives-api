class LabArchivesError(Exception):
    """Base for all labarchives-api exceptions."""


class AuthenticationError(LabArchivesError):
    """Missing credentials or failed authentication flow."""


class ApiError(LabArchivesError):
    """LabArchives API returned an error or unexpected response."""


class NodeExistsError(LabArchivesError):
    """A tree node with the given name already exists (raised by InsertBehavior.Raise)."""


class TraversalError(LabArchivesError):
    """Path traversal failed — an intermediate segment is not a directory."""
