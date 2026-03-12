import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from io import BytesIO

import pytest

import labapi as LA
from labapi import Index

type AnyDict = Mapping[str, AnyDict | str | bool | int | float]
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@pytest.fixture(scope="session")
def la_client():
    """Initializes the LabArchives API Client from .env file."""
    if not os.getenv("ACCESS_KEYID") or not os.getenv("ACCESS_PWD") or not os.getenv("API_URL"):
        pytest.skip("ACCESS_KEYID, ACCESS_PWD, and AUTH_URL required for integration tests")
    else:
        return LA.Client()


@pytest.fixture(scope="session")
def la_user(la_client: LA.Client):
    """Authenticates the user via auth code or interactive browser."""
    interactive = os.getenv("AUTH_INTERACTIVE", "false").lower() == "true"

    if interactive:
        return la_client.default_authenticate()

    email = os.getenv("AUTH_EMAIL")
    key = os.getenv("AUTH_KEY")
    if not email or not key:
        pytest.skip("AUTH_EMAIL and AUTH_KEY required for non-interactive login.")

    return la_client.login(email, key)


@pytest.fixture(scope="session")
def test_notebook(la_user: LA.User):
    """Opens the specific notebook for testing."""
    nb_name = os.getenv("NOTEBOOK", "My Test Notebook")
    # Search by name slice
    notebooks = la_user.notebooks[Index.Name : nb_name]
    if not notebooks:
        pytest.fail(f"Notebook '{nb_name}' not found.")
    return notebooks[0]


def get_or_create_dir(
    parent: LA.Notebook | LA.NotebookDirectory, name: str
) -> LA.NotebookDirectory:
    """Helper to find a directory by name or create it if missing."""
    existing = parent[Index.Name : name]
    if existing:
        assert isinstance(existing[0], LA.NotebookDirectory)
        return existing[0]
    return parent.create(LA.NotebookDirectory, name)


@pytest.fixture(scope="session")
def root_test_dir(test_notebook: LA.Notebook):
    """Returns the 'LabArchives API Test' directory."""
    return get_or_create_dir(test_notebook, "LabArchives API Test")


@pytest.fixture(scope="session")
def tests_dir(root_test_dir: LA.NotebookDirectory):
    """Returns the 'tests' subdirectory."""
    return get_or_create_dir(root_test_dir, "tests")


def add_readme(workspace: LA.NotebookDirectory, scenario: str, actions: str):
    """Helper to add the required README to the test workspace."""
    readme_page = workspace.create(LA.NotebookPage, "README")
    content = f"SCENARIO: {scenario}\n\nACTIONS TAKEN:\n{actions}"
    readme_page.entries.create(LA.PlainTextEntry, content)


def create_json_rich_text(data: dict) -> str:
    """Formats a dictionary as a JSON string inside an HTML <pre> block."""
    pretty_json = json.dumps(data, indent=4)
    return f"<pre>{pretty_json}</pre>"


def get_or_create_page_with_entry(
    parent: LA.NotebookDirectory,
    name: str,
    entry_type: str,
    data: LA.Attachment | str,
) -> LA.NotebookPage:
    """Finds a page by name. If it exists, returns it.
    If not, creates the page and adds the specified entry.
    """
    existing = parent[Index.Name : name]
    if len(existing) > 0:
        assert isinstance(existing[0], LA.NotebookPage)
        return existing[0]

    new_page = parent.create(LA.NotebookPage, name)
    new_page.entries.create(LA.Entry.class_of(entry_type), data)  # type: ignore
    return new_page


def get_or_create_page_with_json(
    parent: LA.NotebookDirectory, name: str, data: dict
) -> LA.NotebookPage:
    """Finds a page by name. If it exists, returns it.
    If not, creates the page and uses the new dual-entry JSON system.
    """
    existing = parent[Index.Name : name]
    if len(existing) > 0:
        return existing[0]

    new_page = parent.create(LA.NotebookPage, name)
    # create_json_entry returns (AttachmentEntry, TextEntry)
    new_page.entries.create_json_entry(data)
    return new_page


@pytest.fixture(scope="session")
def data_dir_structure(root_test_dir: LA.NotebookDirectory):
    data_dir = get_or_create_dir(root_test_dir, "data")
    m1_dir = get_or_create_dir(data_dir, "method_1")

    # 1. method_1/meta.json using the new dual-entry system
    get_or_create_page_with_json(m1_dir, "meta.json", {"name": "", "description": ""})

    subjects_dir = get_or_create_dir(m1_dir, "subjects")

    for i in range(1, 4):
        subj_name = f"subj_{i}"
        s_dir = get_or_create_dir(subjects_dir, subj_name)

        # Subject meta.json using the new system
        gender = "male" if i % 2 == 0 else "female"
        get_or_create_page_with_json(
            s_dir, "meta.json", {"id": f"test subject {i} id", "gender": gender}
        )

        sess_root = get_or_create_dir(s_dir, "sessions")
        sess_1 = get_or_create_dir(sess_root, "1")

        # data.json (Raw experimental data remains a standard attachment)
        if not sess_1[Index.Name : "data.json"]:
            from pathlib import Path

            with open(Path(__file__).parent / "test_entry.json", "rb") as f:
                data_att = LA.Attachment.from_file(f)
                sess_1.create(LA.NotebookPage, "data.json").entries.create(
                    LA.AttachmentEntry, data_att
                )

        # notes.txt
        if not sess_1[Index.Name : "notes.txt"]:
            n_page = sess_1.create(LA.NotebookPage, "notes.txt")
            n_page.entries.create(
                LA.AttachmentEntry,
                LA.Attachment(BytesIO(b""), "text/plain", "notes.txt", "Notes"),
            )

    return data_dir


@pytest.fixture
def test_env(
    request: pytest.FixtureRequest,
    tests_dir: LA.NotebookDirectory,
    data_dir_structure: LA.NotebookDirectory,
):
    """Creates a timestamped directory for the specific test,
    copies the data structure into it, and returns the workspace.
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    test_folder_name = f"test: {request.node.name} {timestamp}"  # pyright: ignore[reportUnknownMemberType]

    # Create the isolated workspace
    workspace = tests_dir.create(LA.NotebookDirectory, test_folder_name)

    # Copy the baseline data structure into this workspace
    # Note: Using your MixinTreeCopy logic
    data_dir_structure.copy_to(workspace)

    return workspace


def test_add_session_notes(test_env):
    """Scenario: Adding clinician notes to an existing session file."""
    # Setup README
    add_readme(
        test_env,
        "Add new session notes",
        "Added a comment to notes.txt for subject 1 session 1.",
    )

    # Navigate to Subj 1 -> Sessions -> 1 -> notes.txt
    # We navigate through the copy in our test_env
    data_copy = test_env[Index.Name : "data"][0]
    subj1 = data_copy[Index.Name : "method_1"][0][Index.Name : "subjects"][0][
        Index.Name : "subj_1"
    ][0]
    notes_page = subj1[Index.Name : "sessions"][0][Index.Name : "1"][0][
        Index.Name : "notes.txt"
    ][0]

    # Add the plain text entry
    notes_page.entries.create(LA.PlainTextEntry, "fell asleep during test")

    assert any("fell asleep" in str(e.content) for e in notes_page.entries)


def test_move_and_merge_sessions(test_env):
    """Scenario: Transferring a session from one subject to another."""
    add_readme(
        test_env,
        "Move subject 2's session 1 to subject 1",
        "Renamed S2-S1 to '2', moved to S1, and verified placement.",
    )

    data_copy = test_env[Index.Name : "data"][0]
    subjects = data_copy[Index.Name : "method_1"][0][Index.Name : "subjects"][0]

    s1_sessions = subjects[Index.Name : "subj_1"][0][Index.Name : "sessions"][0]
    s2_sessions = subjects[Index.Name : "subj_2"][0][Index.Name : "sessions"][0]

    # 1. Get Session 1 from Subject 2
    session_to_move = s2_sessions[Index.Name : "1"][0]

    # 2. Rename it to '2' to avoid collision in the destination
    session_to_move.name = "2"

    # 3. Move it to Subject 1's session directory
    session_to_move.move_to(s1_sessions)

    # Verify move
    assert len(s1_sessions[Index.Name : "2"]) > 0
    assert len(s2_sessions[Index.Name : "1"]) == 0


def test_upload_new_session(test_env):
    """Scenario: Creating a second session for a subject."""
    add_readme(
        test_env,
        "Upload a new session",
        "Created 'session 2' in subject 2 with empty notes.",
    )

    data_copy = test_env[Index.Name : "data"][0]
    subj2 = data_copy[Index.Name : "method_1"][0][Index.Name : "subjects"][0][
        Index.Name : "subj_2"
    ][0]
    sess_root = subj2[Index.Name : "sessions"][0]

    # Create session 2
    sess_2 = sess_root.create(LA.NotebookDirectory, "2")
    notes_page = sess_2.create(LA.NotebookPage, "notes.txt")
    notes_page.entries.create(LA.PlainTextEntry, "New session started.")

    assert len(sess_root[Index.Name : "2"]) > 0


def test_fix_metadata(test_env):
    """Scenario: Correcting metadata by updating both the raw JSON and the rich text preview."""
    add_readme(
        test_env,
        "Fix data",
        "Corrected gender field in Subject 1's meta.json by updating both entries in-place.",
    )

    data_copy = test_env[Index.Name : "data"][0]
    subj1 = data_copy[Index.Name : "method_1"][0][Index.Name : "subjects"][0][
        Index.Name : "subj_1"
    ][0]
    meta_page = subj1[Index.Name : "meta.json"][0]

    # Identify the two parts of the JSON entry
    rich_text_entry = None
    attachment_entry = None

    for entry in meta_page.entries:
        if isinstance(entry, LA.TextEntry):
            rich_text_entry = entry
        elif isinstance(entry, LA.AttachmentEntry):
            attachment_entry = entry

    if not rich_text_entry or not attachment_entry:
        pytest.fail("Dual JSON entries (Attachment + Text) not found on page.")

    # 1. Prepare new data
    new_data = {"id": "test subject 1 id", "gender": "male"}
    new_json_bytes = json.dumps(new_data).encode("utf-8")

    # 2. Update the Raw Attachment in-place
    # We create a new Attachment object to pass to the setter
    new_file_content = LA.Attachment(
        backing=BytesIO(new_json_bytes),
        mime_type="application/json",
        filename=attachment_entry.content.filename,  # Keep existing filename
        caption="Updated metadata file via API",
    )
    attachment_entry.content = new_file_content

    # 3. Update the Rich Text Preview in-place
    # We reuse the formatting logic from create_json_entry
    rich_text_entry.content = f"""
<p>Reference Attachment: {attachment_entry.content.filename}</p>
<p>Entry ID: {attachment_entry.id}</p>
<pre>
{json.dumps(new_data, indent=4)}
</pre>
"""

    # Verification
    # Check rich text
    assert "male" in rich_text_entry.content
    # Check raw attachment content
    updated_bytes = attachment_entry.content.read()
    assert b"male" in updated_bytes


def test_delete_subject(test_env):
    """Scenario: Deleting a subject from the dataset."""
    add_readme(
        test_env,
        "Delete subject 3",
        "Renamed and moved Subject 3 to the 'API Deleted Items' directory.",
    )

    # 1. Navigate to Subject 3 within the isolated test environment
    data_copy = test_env[Index.Name : "data"][0]
    subjects_dir = data_copy[Index.Name : "method_1"][0][Index.Name : "subjects"][0]

    # Ensure subject 3 exists before deletion
    subj3_list = subjects_dir[Index.Name : "subj_3"]
    if not subj3_list:
        pytest.fail("Subject 3 not found in the test workspace.")

    subj3 = subj3_list[0]
    assert isinstance(subj3, LA.NotebookDirectory)

    # 2. Execute the deletion
    # This triggers the client logic:
    # - Renames to "subj_3 - Deleted at YYYY-MM-DD..."
    # - Moves to root/"API Deleted Items"
    subj3.delete()

    # 3. Verification
    # Subject 3 should no longer be in the subjects directory
    subjects_dir._populated = False  # Force refresh local children list
    assert len(subjects_dir[Index.Name : "subj_3"]) == 0

    # Verify it exists in the 'API Deleted Items' folder at the notebook root
    # Note: delete() moves it to self._root (the Notebook)
    deleted_items_dir = test_env.root[Index.Name : "API Deleted Items"]
    assert len(deleted_items_dir) > 0

    # Check if any item in the deleted folder starts with the original name
    found_in_trash = any(
        deleted_items_dir[0][item].name.startswith("subj_3 - Deleted at")
        for item in deleted_items_dir[0]
    )
    assert found_in_trash
