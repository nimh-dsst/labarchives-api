import xml.etree.ElementTree as ET
from io import BytesIO
from typing import Any, Union

from requests import Response

USER_ACCESS_ELEMENTS: list[str] = [
    "id",
    "fullname",
    "first-name",
    "last-name",
    "email",
    "orcid",
    "can-own-notebooks",
    "is-a-teacher",
    "is-a-student",
    "is-a-researcher",
    "suborganization",
]

NOTEBOOK_ELEMENTS: list[str] = ["id", "name", "is-default"]


def parse_user_access_info_response(response: Response) -> dict[str, Any]:
    """
    Parses the user access information from an XML response.

    Parameters
    ----------
    response : Response
        The HTTP response object containing the XML data.

    Returns
    -------
    dict[str, Any]
        A dictionary containing user access information. The keys are the XML
        element tags, and the values are the corresponding text values or
        boolean values if the type attribute is "boolen".

    Raises
    ------
    ValueError
        If the root tag is not 'user', or if any expected elements are missing
        in the response.

    Notes
    -----
    The function expects the XML response to have a root tag of 'user' and
    specific child elements defined in `USER_ACCESS_ELEMENTS` and
    `NOTEBOOK_ELEMENTS`.
    """
    user_access: dict[str, Any] = {}
    tree: ET.ElementTree = ET.parse(BytesIO(response.content))
    root: ET.Element = tree.getroot()
    if root.tag == "users":
        for ua_element in USER_ACCESS_ELEMENTS:
            element: Union[ET.Element, None] = root.find(ua_element)
            if isinstance(element, ET.Element):
                if element.attrib.get("type") == "boolean" and isinstance(
                    element.text, str
                ):
                    user_access[element.tag] = element.text.lower() == "true"
                else:
                    user_access[element.tag] = element.text
            else:
                raise ValueError(
                    f"user_access_info response did not contain {ua_element}"
                )
        notebooks: list[dict[str, Any]] = []
        for notebook in root.findall(".//notebook"):
            notebook_dict: dict[str, Any] = {}
            for notebook_element in NOTEBOOK_ELEMENTS:
                element = notebook.find(notebook_element)
                if isinstance(element, ET.Element):
                    if element.attrib.get("type") == "boolean" and isinstance(
                        element.text, str
                    ):
                        notebook_dict[element.tag] = (
                            element.text.lower() == "true"
                        )
                    else:
                        notebook_dict[element.tag] = element.text
                else:
                    raise ValueError(
                        f"Notebook element did not contain {notebook_element}!"
                    )
            notebooks.append(notebook_dict)
        user_access["notebooks"] = notebooks
    else:
        raise ValueError("Root tag was not 'user' in response!")

    return user_access
