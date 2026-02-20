"""LabArchives Tree Structure Package.

This package defines the hierarchical structure of LabArchives notebooks,
including abstract base classes for tree nodes and containers, and concrete
implementations for notebooks, directories, and pages.
"""

from .collection import Notebooks
from .directory import NotebookDirectory
from .mixins import AbstractTreeContainer, AbstractTreeNode
from .notebook import Notebook
from .page import NotebookPage

__all__ = [
    "AbstractTreeContainer",
    "AbstractTreeNode",
    "Notebook",
    "NotebookDirectory",
    "NotebookPage",
    "Notebooks",
]
