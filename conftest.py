import pytest


def pytest_configure(config: pytest.Config):
    config.addinivalue_line(
        "markers", "is_interactive: mark test as requiring interactive mode"
    )


def pytest_runtest_setup(item: pytest.Item):
    if "is_interactive" in item.keywords:
        if item.config.getoption("capture") != "no":
            pytest.skip("skipping interactive test in non-interactive mode")
