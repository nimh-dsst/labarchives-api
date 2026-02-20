from __future__ import annotations
from lxml.etree import Element
from typing import Mapping, Callable, Any

type EtreeExtractorDict = Mapping[str, EtreeExtractorDict | Callable[[Any], Any]]


def _flatten_dict(
    val: EtreeExtractorDict, prefix: str = ""
) -> dict[str, Callable[[Any], Any]]:
    """Flattens a nested dictionary.

    Args:
        val: The dictionary to flatten.
        prefix: The prefix to use for the keys.

    Returns:
        A flattened dictionary.
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
    """Converts a string to a boolean.

    Args:
        s: The string to convert.

    Returns:
        The boolean value.
    """
    match s.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            raise ValueError(f"Cannot convert '{s}' to bool")


def extract_etree(_etree: Element, format: EtreeExtractorDict) -> dict[str, Any]:
    """Extracts data from an etree element.

    Args:
        etree: The etree element to extract data from.
        format: The format to use for extraction.

    Returns:
        A dictionary of extracted data.
    """
    flat = _flatten_dict(format)

    items: dict[str, Any] = {}

    for key, mapper in flat.items():
        value = _etree.findtext(f"./{key}")

        if (
            value is None
        ):  # XXX should we collate errors and return at end with the dict or?
            raise ValueError(f"Could not find value for './{key}'")

        try:
            items[key.split("/")[-1]] = mapper(value)
        except ValueError as err:
            raise ValueError(
                f"Could not map value {value} with {mapper.__name__} for './{key}'"
            ) from err

    return items
