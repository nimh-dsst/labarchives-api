import pytest
from pytest import LogCaptureFixture
from labarchives_api.client import LAClient
import logging


@pytest.fixture
def client():
    """Create and authenticate an LAClient instance"""
    client = LAClient()
    response = client.login()
    assert response.status_code == 200, "Failed to login"
    return client


@pytest.fixture
def notebook_name() -> str:
    """Provide the test notebook name"""
    return "DSST Test Notebook"


def test_get_entries_for_page(
    client: LAClient, notebook_name: str, caplog: LogCaptureFixture
):
    """Test getting entries for a specific page named 'API Test'"""
    # Find notebook ID matching notebook_name
    nbid = None
    for notebook in client.ua_info["notebooks"]:
        if notebook["name"] == notebook_name:
            nbid = notebook["id"]
            break

    assert nbid is not None, (
        f"Could not find notebook with name: {notebook_name}"
    )

    pages = client.get_all_pages(nbid)

    # Find the 'API Test' page
    api_test_page = None
    for page in pages:
        display_text = page.find("display-text")
        if display_text is not None and display_text.text == "API Test":
            api_test_page = page
            break

    assert api_test_page is not None, "Could not find 'API Test' page"

    # Get the tree_id for the API Test page
    tree_id = api_test_page.find("tree-id")
    assert tree_id is not None, "Could not find tree-id for API Test page"
    assert tree_id.text is not None, "tree-id element has no text content"

    # Get entries for the page
    response = client.get_entries_for_page(
        nbid=nbid,
        page_tree_id=tree_id.text,  # Now safe because we checked it's not None
        entry_data=True,
        comment_data=True,
    )

    # Verify the response
    assert response.status_code == 200, "Failed to get entries for page"
    assert response.content, "Response content is empty"

    # Parse and verify the XML response
    from io import BytesIO
    from xml.etree import ElementTree as ET

    tree = ET.parse(BytesIO(response.content))
    root = tree.getroot()

    # Verify the response structure
    entries = root.findall(".//entry")
    assert entries is not None, "No entries found in response"

    # Replace print statements with logging
    caplog.set_level("INFO")  # type: ignore
    logging.info(f"\nFound {len(entries)} entries on the API Test page")
    for entry in entries:
        entry_id = entry.find("id")
        if entry_id is not None and entry_id.text:
            logging.info(f"Entry ID: {entry_id.text}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
