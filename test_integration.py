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


def create_json_rich_text(data: dict) -> str:
    """Formats a dictionary as a JSON string inside an HTML <pre> block."""
    pretty_json = json.dumps(data, indent=4)
    return f"<pre>{pretty_json}</pre>"

def get_or_create_page_with_entry(
    parent: LA.NotebookDirectory, 
    name: str, 
    entry_type: str, 
    data: LA.Attachment | str
) -> LA.NotebookPage:
    """
    Finds a page by name. If it exists, returns it.
    If not, creates the page and adds the specified entry.
    """
    existing = parent[Index.Name:name]
    if len(existing) > 0:
        assert isinstance(existing[0], LA.NotebookPage)
        return existing[0]
    
    new_page = parent.create_page(name)
    new_page.entries.create_entry(entry_type, data) # type: ignore
    return new_page

@pytest.fixture(scope="session")
def data_dir_structure(root_test_dir: LA.NotebookDirectory):
    data_dir = get_or_create_dir(root_test_dir, "data")
    m1_dir = get_or_create_dir(data_dir, "method_1")
    
    # 1. method_1/meta.json as Rich Text
    get_or_create_page_with_entry(
        m1_dir, "meta.json", "text entry",
        create_json_rich_text({"name": "", "description": ""})
    )
    
    subjects_dir = get_or_create_dir(m1_dir, "subjects")

    for i in range(1, 4):
        subj_name = f"subj_{i}"
        s_dir = get_or_create_dir(subjects_dir, subj_name)
        
        # Subject meta.json as Rich Text
        gender = "male" if i % 2 == 0 else "female"
        get_or_create_page_with_entry(
            s_dir, "meta.json", "text entry",
            create_json_rich_text({"id": f"test subject {i} id", "gender": gender})
        )
        
        sess_root = get_or_create_dir(s_dir, "sessions")
        sess_1 = get_or_create_dir(sess_root, "1")
        
        # data.json (Remains an Attachment for raw data)
        if not sess_1[Index.Name:"data.json"]:
            with open("test_entry.json", "rb") as f:
                data_att = LA.Attachment.from_file(f)
                get_or_create_page_with_entry(sess_1, "data.json", "attachment", data_att)
        
        # notes.txt (Remains an Attachment)
        get_or_create_page_with_entry(
            sess_1, "notes.txt", "attachment",
            LA.Attachment(BytesIO(b""), "text/plain", "notes.txt", "Notes")
        )

    return data_dir

def test_1(data_dir_structure):
    pass