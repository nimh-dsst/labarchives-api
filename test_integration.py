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


@pytest.fixture(scope="session")
def data_dir_structure(root_test_dir: LA.NotebookDirectory):
    """
    Creates/Returns the complex 'data' directory structure using Attachments.
    """
    data_dir = get_or_create_dir(root_test_dir, "data")
    m1_dir = get_or_create_dir(data_dir, "method_1")
    
    # 1. method_1/meta.json as an Attachment
    m1_meta_data = {"name": "", "description": ""}
    m1_attachment = create_json_attachment(m1_meta_data, "meta.json")
    
    m1_page = m1_dir.create_page("meta.json")
    m1_page.entries.create_entry("attachment", m1_attachment)
    
    subjects_dir = get_or_create_dir(m1_dir, "subjects")

    # 2. Create 3 subjects
    for i in range(1, 4):
        subj_name = f"subj_{i}"
        s_dir = get_or_create_dir(subjects_dir, subj_name)
        
        # Subject meta.json attachment
        gender = "male" if i % 2 == 0 else "female"
        s_meta_attachment = create_json_attachment(
            {"id": f"test subject {i} id", "gender": gender}, 
            "meta.json"
        )
        s_meta_page = s_dir.create_page("meta.json")
        s_meta_page.entries.create_entry("attachment", s_meta_attachment)
        
        # sessions/1/
        sess_root = get_or_create_dir(s_dir, "sessions")
        sess_1 = get_or_create_dir(sess_root, "1")
        
        # data.json (Upload from local file via Attachment.from_file)
        # We assume the file exists in the project root as specified
        with open("test_entry.json", "rb") as f:
            # We use the existing class method if it supports the buffer, 
            # or wrap it manually to ensure correct mime_type
            data_attachment = LA.Attachment(
                backing=f, 
                mime_type="text/json",
                filename="data.json",
                caption="Main data file"
            )

            d_page = sess_1.create_page("data.json")
            d_page.entries.create_entry("attachment", data_attachment)
        
        
        
        # notes.txt (Empty file attachment)
        notes_attachment = LA.Attachment(
            backing=BytesIO(b""),
            mime_type="text/plain",
            filename="notes.txt",
            caption="Session notes"
        )
        n_page = sess_1.create_page("notes.txt")
        n_page.entries.create_entry("attachment", notes_attachment)

    return data_dir

def test_1(data_dir_structure):
    pass