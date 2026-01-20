import os
import json
import pytest
from io import BytesIO
import main as LA
from main import Index
from typing import Mapping
from dotenv import load_dotenv

type AnyDict = Mapping[str, AnyDict | str | bool | int | float]

load_dotenv()

def create_json_attachment(data: AnyDict, filename: str) -> LA.Attachment:
    """Helper to wrap a dictionary into a LabArchives Attachment object."""
    content = json.dumps(data).encode("utf-8")
    # Using BytesIO to simulate a file-like object for on-the-fly JSON
    backing = BytesIO(content)
    return LA.Attachment(
        backing=backing,
        mime_type="text/json",
        filename=filename,
        caption=f"{filename}"
    )

@pytest.fixture(scope="session")
def la_client():
    """Initializes the LabArchives API Client."""
    api_url = os.getenv("API_URL", "https://api.labarchives.com")
    akid = os.getenv("ACCESS_KEYID")
    akpass = os.getenv("ACCESS_PWD")
    
    if not akid or not akpass:
        pytest.fail("ACCESS_KEYID or ACCESS_PWD environment variables not set.")
        
    return LA.Client(base_url=api_url, akid=akid, akpass=akpass)

@pytest.fixture(scope="session")
def la_user(la_client: LA.Client):
    """Authenticates the user via auth code or interactive browser."""
    interactive = os.getenv("AUTH_INTERACTIVE", "false").lower() == "true"
    
    if interactive:
        return la_client.default_authenticate()
    
    email = os.getenv("AUTH_EMAIL")
    key = os.getenv("AUTH_KEY")
    if not email or not key:
        pytest.fail("AUTH_EMAIL and AUTH_KEY required for non-interactive login.")
        
    return la_client.login_authcode(email, key)

@pytest.fixture(scope="session")
def test_notebook(la_user: LA.User):
    """Opens the specific notebook for testing."""
    nb_name = os.getenv("NOTEBOOK", "My Test Notebook")
    # Search by name slice
    notebooks = la_user.notebooks[Index.Name:nb_name]
    if not notebooks:
        pytest.fail(f"Notebook '{nb_name}' not found.")
    return notebooks[0]

def get_or_create_dir(parent: LA.NotebookTreeNode, name: str) -> LA.NotebookDirectory:
    """Helper to find a directory by name or create it if missing."""
    existing = parent[Index.Name:name]
    if existing:
        assert isinstance(existing[0], LA.NotebookDirectory)
        return existing[0]
    return parent.create_directory(name)

@pytest.fixture(scope="session")
def root_test_dir(test_notebook: LA.Notebook):
    """Returns the 'LabArchives API Test' directory."""
    return get_or_create_dir(test_notebook, "LabArchives API Test")

@pytest.fixture(scope="session")
def tests_dir(root_test_dir: LA.NotebookDirectory):
    """Returns the 'tests' subdirectory."""
    return get_or_create_dir(root_test_dir, "tests")


def get_or_create_page_with_attachment(
    parent: LA.NotebookDirectory, 
    name: str, 
    attachment: LA.Attachment
) -> LA.NotebookPage:
    """
    Finds a page by name. If it exists, returns it.
    If not, creates the page and uploads the provided attachment.
    """
    existing = parent[Index.Name:name]
    if len(existing) > 0:
        assert isinstance(existing[0], LA.NotebookPage)
        return existing[0] # Assume entries exist if page exists
    
    new_page = parent.create_page(name)
    new_page.entries.create_entry("attachment", attachment)
    return new_page

@pytest.fixture(scope="session")
def data_dir_structure(root_test_dir: LA.NotebookDirectory):
    data_dir = get_or_create_dir(root_test_dir, "data")
    m1_dir = get_or_create_dir(data_dir, "method_1")
    
    # 1. method_1/meta.json
    # We still create the Attachment object here, but only call create_entry if needed
    get_or_create_page_with_attachment(
        m1_dir, "meta.json",
        create_json_attachment({"name": "", "description": ""}, "meta.json")
    )
    
    subjects_dir = get_or_create_dir(m1_dir, "subjects")

    for i in range(1, 4):
        subj_name = f"subj_{i}"
        s_dir = get_or_create_dir(subjects_dir, subj_name)
        
        # Subject meta.json
        gender = "male" if i % 2 == 0 else "female"
        get_or_create_page_with_attachment(
            s_dir, "meta.json",
            create_json_attachment({"id": f"test subject {i} id", "gender": gender}, "meta.json")
        )
        
        sess_root = get_or_create_dir(s_dir, "sessions")
        sess_1 = get_or_create_dir(sess_root, "1")
        
        # data.json from local file
        # We only open the file if the page doesn't exist to save I/O
        if not sess_1[Index.Name:"data.json"]:
            with open("test_entry.json", "rb") as f:
                data_att = LA.Attachment.from_file(f)
                get_or_create_page_with_attachment(sess_1, "data.json", data_att)
        
        # notes.txt
        get_or_create_page_with_attachment(
            sess_1, "notes.txt",
            LA.Attachment(BytesIO(b""), "text/plain", "notes.txt", "Notes")
        )

    return data_dir

def test_1(data_dir_structure):
    pass