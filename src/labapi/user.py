from __future__ import annotations
from io import BufferedIOBase
from typing import Any, Mapping, Sequence, TYPE_CHECKING
from warnings import deprecated

if TYPE_CHECKING:
    from .client import Client
from .util.notebookinit import NotebookInit

from .util.extract import extract_etree


class User:
    """A LabArchives user."""

    def __init__(
        self,
        uid: str,
        auto_login: bool,
        notebooks: Sequence[NotebookInit],
        client: Client,
    ):
        super().__init__()
        self._id = uid
        self._can_refresh = auto_login
        self._notebooks = Notebooks(notebooks, self)
        self._client = client

    @property
    def id(self):
        return self._id

    @property
    def client(self):
        return self._client

    def api_get(self, api_method_uri: str | Sequence[str], **kwargs: Any):
        """Makes a GET request to the LabArchives API.

        Args:
            api_method_uri: The API method to call.
            **kwargs: Additional arguments to pass to the API method.

        Returns:
            The response from the API.
        """
        return self._client.api_get(api_method_uri, **kwargs, uid=self._id)

    def api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ):
        return self._client.api_post(api_method_uri, body, **kwargs, uid=self._id)

    @deprecated("LabArchives Auth Refreshing is unstable and inconsistent")
    def refresh(self, *, user_requested: bool = False):
        """Refreshes the user's session.

        Args:
            user_requested: Whether the refresh request is explicitly requested by the user
        """
        if not self._can_refresh and not user_requested:
            raise RuntimeError("User session cannot be automatically refreshed")

        uid_tree = self.api_get("users/user_info_via_id", authenticated=user_requested)
        self._id = uid_tree.findtext(".//users/id")  # TODO extract etree
        # XXX should we refresh ability to auto_login and notebooks here?

        # TODO fill in rest of function

    def get_max_upload_size(self) -> int:
        """Gets the maximum upload size for the user.

        Returns:
            The maximum upload size in bytes.
        """
        # NOTE the api reference doesn't explain what unit this is, so I'm going to treat this as bytes
        return extract_etree(
            self.api_get("users/max_file_size"), {"max-file-size": int}
        )["max-file-size"]

    @property
    def notebooks(self):
        """The user's notebooks."""
        return self._notebooks
