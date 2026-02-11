from dataclasses import dataclass


@dataclass
class NotebookInit:
    """Initialisation data for a Notebook."""

    id: str
    name: str
    is_default: bool
