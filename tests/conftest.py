import pytest


def pytest_addoption(parser):
    """Registers custom ini options so PyTest recognizes them."""
    parser.addini(
        "test_notebook", type="string", help="Target notebook for tests"
    )
    parser.addini(
        "test_page_name", type="string", help="Target page name for tests"
    )


@pytest.fixture(scope="session")
def test_notebook_name(pytestconfig):
    """Fixture to get the 'test_notebook' value from pytest.ini."""
    name = pytestconfig.getini("test_notebook")
    if not name:
        pytest.fail(
            "The 'test_notebook' value must be set in pytest.ini. Example: test_notebook = \"MyNotebook\""
        )
    return name


@pytest.fixture(scope="session")
def target_page_name(pytestconfig):  # Renamed fixture for clarity
    """Fixture to get the 'test_page_name' value from pytest.ini."""
    name = pytestconfig.getini("test_page_name")
    if not name:
        pytest.fail(
            "The 'test_page_name' value must be set in pytest.ini. Example: test_page_name = \"MyPage\""
        )
    return name
