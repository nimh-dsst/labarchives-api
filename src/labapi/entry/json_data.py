"""JSON Data Type Module.

This module defines a recursive type alias, :attr:`~labapi.entry.json_data.JsonData`,
to represent data structures that can be serialized to or deserialized from JSON.
"""

from collections.abc import Mapping, Sequence

type JsonData = (
    Sequence["JsonData"] | Mapping[str, "JsonData"] | str | bool | int | float | None
)
"""
A recursive type alias representing any data structure that can be
serialized to or deserialized from JSON.

This includes:
    - `Sequence[JsonData]` (e.g., lists, tuples)
    - `Mapping[str, JsonData]` (e.g., dictionaries)
    - `str`
    - `bool`
    - `int`
    - `float`
    - `None`
"""
