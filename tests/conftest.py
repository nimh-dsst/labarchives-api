"""Pytest configuration for selecting integration tests."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser):
    """Register the command-line flag for running integration tests."""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run tests marked as integration tests",
    )


def pytest_configure(config: pytest.Config):
    """Register the custom marker used by integration tests."""
    config.addinivalue_line(
        "markers", "integration: mark test as requiring live LabArchives access"
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip integration tests unless the integration flag was requested."""
    if config.getoption("--integration"):
        return

    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []

    for item in items:
        if "integration" in item.keywords:
            deselected.append(item)
        else:
            selected.append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected
