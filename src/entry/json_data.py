from typing import Mapping, Sequence

type JsonData = (
    Sequence[JsonData] | Mapping[str, JsonData] | str | bool | int | float | None
)
