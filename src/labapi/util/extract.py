"""XML Extraction Utilities Module.

This module provides utility functions for extracting data from `lxml.etree.Element`
objects, including flattening dictionaries for easier processing, converting
strings to booleans, and a general-purpose XML extraction function.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lxml.etree import Element

type EtreeExtractorDict = Mapping[str, "EtreeExtractorDict | Callable[[Any], Any]"]
"""
Type alias for a dictionary used to define the structure and extraction
logic for `lxml.etree.Element` objects.

It can be nested, where keys represent XML element tags and values are either
another `EtreeExtractorDict` for nested structures or a `Callable` to process
the text content of the element.
"""


def _flatten_dict(
    val: EtreeExtractorDict, prefix: str = ""
) -> dict[str, Callable[[Any], Any]]:
    """Recursively flattens a nested dictionary of `EtreeExtractorDict` into a single-level dictionary.

    The keys in the flattened dictionary represent the full path to the callable
    extractor, separated by '/'.

    :param val: The nested dictionary to flatten.
    :param prefix: The current prefix for keys during recursion. Defaults to an empty string.
    :returns: A flattened dictionary where keys are paths and values are callable extractors.
    :raises ValueError: If an empty string is used as a key in the input dictionary.
    """
    items: dict[str, Callable[[Any], Any]] = {}

    for _key, value in val.items():
        if len(_key) == 0:
            raise ValueError("Key cannot be empty string")

        key = f"{prefix}/{_key}"

        if callable(value):
            items[key] = value
        else:
            items.update(_flatten_dict(value, key))

    return items


def to_bool(s: str) -> bool:
    """Converts a string representation to a boolean value.

    Recognizes "true" (case-insensitive) as True and "false" (case-insensitive) as False.

    :param s: The string to convert.
    :returns: The boolean representation of the string.
    :raises ValueError: If the string cannot be converted to a boolean.
    """
    match s.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            raise ValueError(f"Cannot convert '{s}' to bool")


def extract_etree(_etree: Element, format: EtreeExtractorDict) -> dict[str, Any]:
    """Extracts data from an `lxml.etree.Element` object based on a specified format dictionary.

    This function navigates the XML tree using paths defined in the `format` dictionary
    and applies callable extractors to the text content of the found elements.

    :param _etree: The `lxml.etree.Element` from which to extract data.
    :param format: A dictionary defining the structure and extraction logic.
                   Keys are XML element tags (or paths), and values are either
                   nested `EtreeExtractorDict` or callable functions to process the text.
    :returns: A dictionary containing the extracted and processed data.
    :raises ValueError: If an element specified in the format is not found in the etree,
                        or if a callable extractor fails to process a value.
    """
    flat = _flatten_dict(format)
    leaf_extractors: dict[str, list[tuple[str, Callable[[Any], Any]]]] = {}

    for key, mapper in flat.items():
        leaf_extractors.setdefault(key.split("/")[-1], []).append((key, mapper))

    duplicates = {
        leaf: [path for path, _ in extractors]
        for leaf, extractors in leaf_extractors.items()
        if len(extractors) > 1
    }
    if duplicates:
        duplicate_text = "; ".join(
            f"{leaf}: {', '.join(paths)}"
            for leaf, paths in sorted(duplicates.items())
        )
        raise ValueError(
            "Ambiguous extractor format has duplicate leaf keys: "
            f"{duplicate_text}"
        )

    items: dict[str, Any] = {}

    for leaf, extractors in leaf_extractors.items():
        key, mapper = extractors[0]
        value = _etree.findtext(f"./{key}")

        if (
            value is None
        ):  # XXX should we collate errors and return at end with the dict or?
            raise ValueError(f"Could not find value for './{key}'")

        try:
            items[leaf] = mapper(value)
        except ValueError as err:
            raise ValueError(
                f"Could not map value {value} with {mapper.__name__} for './{key}'"
            ) from err

    return items
