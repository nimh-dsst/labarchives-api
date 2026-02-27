"""LabArchives User Module.

This module defines the :class:`~labapi.user.User` class, which represents an
authenticated user session with the LabArchives API. It provides methods for
interacting with the API on behalf of the user, managing notebooks, and
accessing user-specific information.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from labapi.tree.collection import Notebooks
from labapi.util import extract_etree

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from io import BufferedIOBase

    from labapi.util import NotebookInit

    from .client import Client


class User:
    """Represents an authenticated LabArchives user session.

    This class holds user-specific information such as the user ID and provides
    an interface to interact with the LabArchives API, particularly for
    accessing and managing notebooks and their contents.
    """

    def __init__(
        self,
        uid: str,
        notebooks: Sequence[NotebookInit],
        client: Client,
    ):
        """Initializes a new User session.

        :param uid: The unique ID of the user.
        :type uid: str
        :param notebooks: A sequence of :class:`~labapi.util.notebookinit.NotebookInit` objects
                          representing the notebooks accessible to the user.
        :type notebooks: Sequence[labapi.util.notebookinit.NotebookInit]
        :param client: The :class:`~labapi.client.Client` instance used for API communication.
        :type client: labapi.client.Client
        """
        super().__init__()
        self._id: str = uid
        self._notebooks = Notebooks(notebooks, self)
        self._client = client

    @property
    def id(self) -> str:
        """The unique ID of the user.

        :returns: The user's ID.
        :rtype: str
        """
        return self._id

    @property
    def client(self) -> Client:
        """The :class:`~labapi.client.Client` instance associated with this user session.

        :returns: The client instance.
        :rtype: labapi.client.Client
        """
        return self._client

    def api_get(self, api_method_uri: str | Sequence[str], **kwargs: Any):
        """Makes a GET request to the LabArchives API on behalf of the authenticated user.

        This method automatically appends the user's ID to the API call.

        :param api_method_uri: The API method URI (e.g., "get_user_settings").
                               Can be a string or a sequence of strings representing path segments.
        :type api_method_uri: str or Sequence[str]
        :param kwargs: Additional query parameters to pass to the API method.
        :type kwargs: Any
        :returns: The response from the API, typically an lxml Element.
        :rtype: lxml.etree.Element
        :raises RuntimeError: If the API request fails.
        """
        return self._client.api_get(api_method_uri, **kwargs, uid=self._id)

    def api_post(
        self,
        api_method_uri: str | Sequence[str],
        body: Mapping[str, str] | BufferedIOBase,
        **kwargs: Any,
    ):
        """Makes a POST request to the LabArchives API on behalf of the authenticated user.

        This method automatically appends the user's ID to the API call.

        :param api_method_uri: The API method URI (e.g., "create_entry").
                               Can be a string or a sequence of strings representing path segments.
        :type api_method_uri: str or Sequence[str]
        :param body: The request body, which can be a mapping of form data or a file-like object.
        :type body: Mapping[str, str] or BufferedIOBase
        :param kwargs: Additional query parameters to pass to the API method.
        :type kwargs: Any
        :returns: The response from the API, typically an lxml Element.
        :rtype: lxml.etree.Element
        :raises RuntimeError: If the API request fails.
        """
        return self._client.api_post(api_method_uri, body, **kwargs, uid=self._id)

    def get_max_upload_size(self) -> int:
        """Retrieves the maximum allowed file upload size for the user from the LabArchives API.

        The unit of the returned value is bytes.

        :returns: The maximum upload size in bytes.
        :rtype: int
        :raises RuntimeError: If the API request fails.
        """
        return extract_etree(
            self.api_get("users/max_file_size"), {"max-file-size": int}
        )["max-file-size"]

    @property
    def notebooks(self) -> Notebooks:
        """Provides access to the user's notebooks.

        :returns: A :class:`~labapi.tree.collection.Notebooks` object managing the user's notebooks.
        :rtype: labapi.tree.collection.Notebooks
        """
        return self._notebooks
