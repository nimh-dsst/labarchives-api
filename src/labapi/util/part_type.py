"""Entry part type utilities.

This module provides utilities for validating, normalizing, and serializing
LabArchives entry part types (also known as content types).

Type aliases are provided for static type checking:
- :type:`PartType`: All recognized LabArchives entry types
- :type:`ImplementedPartType`: Entry types with implementation support in labapi
"""

from typing import Literal, TypeGuard

#: All known LabArchives entry part types.
_ALL_PART_TYPES = (
    "attachment",
    "plain text entry",
    "heading",
    "text entry",
    "widget entry",
    "sketch entry",
    "reference entry",
    "equation entry",
    "assignment entry",
)

type PartType = Literal[
    "attachment",
    "plain text entry",
    "heading",
    "text entry",
    "widget entry",
    "sketch entry",
    "reference entry",
    "equation entry",
    "assignment entry",
]

#: Part types that have been implemented in labapi.
#: Other types may be recognized but not fully supported.
_ALL_IMPLEMENTED_PART_TYPES = (
    "attachment",
    "plain text entry",
    "heading",
    "text entry",
    "widget entry",  # NOTE only partially implemented
)

type ImplementedPartType = Literal[
    "attachment", "plain text entry", "heading", "text entry", "widget entry"
]

#: Mapping of normalized part types to their serialized form.
#: Used for special cases where the API expects different capitalization.
_PART_TYPE_MAPPING = {
    "attachment": "Attachment",
}


def get_normalized_part_type(part_type: str) -> str:
    """Normalizes a part type string to lowercase and strips whitespace.

    This function ensures consistent comparison of part types by converting
    them to a canonical form. Use this before calling :func:`is_part_type` or
    :func:`is_valid_part_type` if the input may have mixed case or whitespace.

    :param part_type: The raw part type string from the API or user input.
    :type part_type: str
    :returns: The normalized part type (lowercase, stripped).
    :rtype: str

    Example:
        >>> get_normalized_part_type("  Attachment  ")
        'attachment'
        >>> get_normalized_part_type("TEXT ENTRY")
        'text entry'
    """
    return part_type.lower().strip()


def is_part_type(
    part_type: str,
) -> TypeGuard[PartType]:
    """Checks if a part type is recognized by LabArchives.

    This function validates whether a given part type is one of the known
    LabArchives entry types, regardless of whether it's implemented in labapi.

    Acts as a :class:`~typing.TypeGuard`, narrowing the type to :type:`PartType`
    when it returns True.

    .. note::
       This function expects a **normalized** part type (lowercase, stripped).
       Use :func:`get_normalized_part_type` first if the input may have mixed case.

    :param part_type: The normalized part type string to check.
    :type part_type: str
    :returns: True if the part type is recognized, False otherwise.
    :rtype: TypeGuard[PartType]

    Example:
        >>> is_part_type("attachment")
        True
        >>> is_part_type("sketch entry")
        True
        >>> is_part_type("unknown type")
        False
        >>> is_part_type("Attachment")  # Not normalized!
        False
    """
    return part_type in _ALL_PART_TYPES


def is_valid_part_type(part_type: str) -> TypeGuard[ImplementedPartType]:
    """Checks if a part type is both recognized and implemented in labapi.

    This function validates whether a given part type is not only recognized
    by LabArchives, but also has implementation support in labapi.

    Acts as a :class:`~typing.TypeGuard`, narrowing the type to
    :type:`ImplementedPartType` when it returns True.

    .. note::
       This function expects a **normalized** part type (lowercase, stripped).
       Use :func:`get_normalized_part_type` first if the input may have mixed case.

    :param part_type: The normalized part type string to check.
    :type part_type: str
    :returns: True if the part type is recognized and implemented, False otherwise.
    :rtype: TypeGuard[ImplementedPartType]

    Example:
        >>> is_valid_part_type("attachment")
        True
        >>> is_valid_part_type("text entry")
        True
        >>> is_valid_part_type("sketch entry")
        False  # Recognized but not implemented
        >>> is_valid_part_type("unknown type")
        False  # Not recognized at all
    """
    return part_type in _ALL_PART_TYPES and part_type in _ALL_IMPLEMENTED_PART_TYPES


def serialize_part_type(part_type: str) -> str:
    """Serializes a part type to the format expected by the LabArchives API.

    Some part types require specific capitalization when sent to the API.
    This function normalizes the input and handles those special cases using
    the mapping table.

    :param part_type: The part type string (normalized or raw).
    :type part_type: str
    :returns: The serialized part type string suitable for API requests.
    :rtype: str

    Example:
        >>> serialize_part_type("attachment")
        'Attachment'  # Capitalized for API
        >>> serialize_part_type("text entry")
        'text entry'  # No special mapping, returned as-is
        >>> serialize_part_type("  ATTACHMENT  ")
        'Attachment'  # Normalized then mapped
    """
    normalized = get_normalized_part_type(part_type)

    return _PART_TYPE_MAPPING.get(normalized, part_type)
