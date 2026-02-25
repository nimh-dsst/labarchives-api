Complete Workflows
==================

This tutorial provides complete, real-world workflows for common LabArchives tasks using **labapi**.

Prerequisites
-------------

* Authenticated user session
* Understanding of basic operations from previous tutorials

These examples are production-ready and can be adapted to your specific needs.

Workflow 1: Add Session Notes
------------------------------

**Scenario:** Add clinician notes to an existing experimental session.

.. code-block:: python

   from labapi import Client, Index

   client = Client()
   user = client.login_authcode(email, auth_code)

   # Navigate to the session notes file
   notebook = user.notebooks[Index.Name : "Research"][0]
   data_dir = notebook[Index.Name : "data"][0]
   method1 = data_dir[Index.Name : "method_1"][0]
   subjects = method1[Index.Name : "subjects"][0]
   subj1 = subjects[Index.Name : "subj_1"][0]
   sessions = subj1[Index.Name : "sessions"][0]
   session1 = sessions[Index.Name : "1"][0]
   notes_page = session1[Index.Name : "notes.txt"][0]

   # Add a plain text entry with the notes
   notes_page.entries.create_entry(
       "plain text entry",
       "Patient fell asleep during test. Session paused at 14:30."
   )

   print("Notes added successfully")

**Key Points:**

* Navigate through the directory structure to find the target page
* Use ``create_entry`` to add notes without overwriting existing content
* Plain text entries are best for simple notes

Workflow 2: Move Session Between Subjects
------------------------------------------

**Scenario:** Transfer a session from one subject to another (e.g., correcting a data entry error).

.. code-block:: python

   from labapi import Client, Index

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[Index.Name : "Research"][0]

   # Navigate to the subjects directory
   subjects = (
       notebook[Index.Name : "data"][0]
               [Index.Name : "method_1"][0]
               [Index.Name : "subjects"][0]
   )

   # Get session directories for both subjects
   subj1_sessions = subjects[Index.Name : "subj_1"][0][Index.Name : "sessions"][0]
   subj2_sessions = subjects[Index.Name : "subj_2"][0][Index.Name : "sessions"][0]

   # Get the session to move from Subject 2
   session_to_move = subj2_sessions[Index.Name : "1"][0]

   # Rename to avoid collision at destination
   session_to_move.name = "2"

   # Move to Subject 1's sessions
   session_to_move.move_to(subj1_sessions)

   # Verify the move
   moved_sessions = subj1_sessions[Index.Name : "2"]
   if moved_sessions:
       print(f"Session moved successfully to {moved_sessions[0].name}")

   # Verify it's gone from source
   subj2_sessions._populated = False  # Force refresh
   remaining = subj2_sessions[Index.Name : "1"]
   if not remaining:
       print("Session removed from original location")

**Key Points:**

* Rename before moving to avoid name collisions
* Use ``move_to()`` to relocate directories or pages
* Clear cache (``_populated = False``) to verify changes

Workflow 3: Upload New Session Data
------------------------------------

**Scenario:** Create a new experimental session with data files.

.. code-block:: python

   from labapi import Client, Index, Attachment
   from io import BytesIO

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[Index.Name : "Research"][0]

   # Navigate to subject's sessions directory
   sessions_dir = (
       notebook[Index.Name : "data"][0]
               [Index.Name : "method_1"][0]
               [Index.Name : "subjects"][0]
               [Index.Name : "subj_2"][0]
               [Index.Name : "sessions"][0]
   )

   # Create new session directory
   session2 = sessions_dir.create_directory("2")

   # Create notes file
   notes_page = session2.create_page("notes.txt")
   notes_page.entries.create_entry(
       "plain text entry",
       "New session started. All equipment calibrated."
   )

   # Upload data file
   data_page = session2.create_page("data.json")
   with open("session_2_data.json", "rb") as f:
       attachment = Attachment.from_file(f)
       data_page.entries.create_entry("attachment", attachment)

   print(f"Session 2 created with {len(list(session2))} files")

**Key Points:**

* Create directory structure before adding files
* Use ``create_page()`` for each file
* Attach files with ``Attachment.from_file()``

Workflow 4: Fix Metadata
-------------------------

**Scenario:** Correct metadata in a JSON file using the dual-entry system (see :doc:`json-pattern`).

.. code-block:: python

   from labapi import Client, Index, Attachment, TextEntry, AttachmentEntry
   from io import BytesIO
   import json

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[Index.Name : "Research"][0]

   # Navigate to the metadata page
   subj1 = (
       notebook[Index.Name : "data"][0]
               [Index.Name : "method_1"][0]
               [Index.Name : "subjects"][0]
               [Index.Name : "subj_1"][0]
   )
   meta_page = subj1[Index.Name : "meta.json"][0]

   # Find the dual JSON entries
   rich_text_entry = None
   attachment_entry = None

   for entry in meta_page.entries:
       if isinstance(entry, TextEntry):
           rich_text_entry = entry
       elif isinstance(entry, AttachmentEntry):
           attachment_entry = entry

   if not rich_text_entry or not attachment_entry:
       raise ValueError("Dual JSON entries not found")

   # Prepare corrected data
   corrected_data = {
       "id": "test subject 1 id",
       "gender": "male"  # Correcting from "female" to "male"
   }

   # Update the raw attachment
   json_bytes = json.dumps(corrected_data, indent=2).encode("utf-8")
   new_attachment = Attachment(
       backing=BytesIO(json_bytes),
       mime_type="application/json",
       filename=attachment_entry.content.filename,
       caption="Updated metadata"
   )
   attachment_entry.content = new_attachment

   # Update the rich text preview
   rich_text_entry.content = f"""
   <p>Reference Attachment: {attachment_entry.content.filename}</p>
   <p>Entry ID: {attachment_entry.id}</p>
   <pre>
   {json.dumps(corrected_data, indent=4)}
   </pre>
   """

   print("Metadata corrected successfully")

**Key Points:**

* The dual-entry JSON pattern uses both an attachment (raw data) and text (preview)
* Update both entries to keep them synchronized
* See :doc:`json-pattern` for details on this pattern

Workflow 5: Delete Subject
---------------------------

**Scenario:** Remove a subject from the dataset (soft delete).

.. code-block:: python

   from labapi import Client, Index

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[Index.Name : "Research"][0]

   # Navigate to the subject
   subjects_dir = (
       notebook[Index.Name : "data"][0]
               [Index.Name : "method_1"][0]
               [Index.Name : "subjects"][0]
   )

   subj3_list = subjects_dir[Index.Name : "subj_3"]
   if not subj3_list:
       raise ValueError("Subject 3 not found")

   subj3 = subj3_list[0]

   # Delete the subject
   # This renames it with "- Deleted at [timestamp]"
   # and moves it to "API Deleted Items" folder at notebook root
   subj3.delete()

   # Verify deletion
   subjects_dir._populated = False  # Force refresh
   remaining = subjects_dir[Index.Name : "subj_3"]
   if not remaining:
       print("Subject 3 deleted successfully")

   # Check the deleted items folder
   deleted_items = notebook.root[Index.Name : "API Deleted Items"]
   if deleted_items:
       print(f"Deleted item moved to: {deleted_items[0].name}")
       for item in deleted_items[0]:
           if "subj_3" in item.name:
               print(f"  Found: {item.name}")

**Key Points:**

* ``delete()`` performs a soft delete (not permanent)
* Items are moved to "API Deleted Items" folder
* Items are renamed with deletion timestamp
* Permanently delete via LabArchives web interface if needed

Workflow 6: Batch Data Upload
------------------------------

**Scenario:** Upload multiple experimental data files to organized directories.

.. code-block:: python

   from labapi import Client, Index, Attachment
   from pathlib import Path
   import json

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[0]

   # Create base structure
   experiments = notebook.create_directory("Batch Experiments")

   # Upload data for multiple experiments
   data_dir = Path("./experimental_data")

   for exp_dir in data_dir.iterdir():
       if exp_dir.is_dir():
           # Create experiment directory
           exp = experiments.create_directory(exp_dir.name)

           # Upload metadata
           meta_file = exp_dir / "metadata.json"
           if meta_file.exists():
               with open(meta_file, "r") as f:
                   metadata = json.load(f)

               # Use dual-entry JSON pattern
               meta_page = exp.create_page("metadata.json")
               meta_page.entries.create_json_entry(metadata)

           # Upload all data files
           for data_file in exp_dir.glob("*.csv"):
               page = exp.create_page(data_file.name)
               with open(data_file, "rb") as f:
                   attachment = Attachment.from_file(f)
                   page.entries.create_entry("attachment", attachment)

               print(f"Uploaded: {exp_dir.name}/{data_file.name}")

   print("Batch upload complete")

**Key Points:**

* Organize data into directories before uploading
* Use ``create_json_entry()`` for metadata (dual-entry pattern)
* Process files in batches with loops

Workflow 7: Export Notebook Data
---------------------------------

**Scenario:** Download all data from a notebook for backup or analysis.

.. code-block:: python

   from labapi import Client, Index, NotebookDirectory, NotebookPage
   from labapi import AttachmentEntry
   from pathlib import Path

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[Index.Name : "Research"][0]

   # Create output directory
   output_dir = Path(f"./export_{notebook.name}")
   output_dir.mkdir(exist_ok=True)

   def export_node(node, current_path):
       """Recursively export all content from a node."""
       for item in node:
           item_path = current_path / item.name

           if isinstance(item, NotebookDirectory):
               # Create directory
               item_path.mkdir(exist_ok=True)
               # Recurse into subdirectory
               export_node(item, item_path)

           elif isinstance(item, NotebookPage):
               # Download all attachments from this page
               page_dir = item_path
               page_dir.mkdir(exist_ok=True)

               for i, entry in enumerate(item.entries):
                   if isinstance(entry, AttachmentEntry):
                       attachment = entry.content
                       data = attachment.read()

                       # Save attachment
                       file_path = page_dir / attachment.filename
                       with open(file_path, "wb") as f:
                           f.write(data)

                       print(f"Downloaded: {file_path}")

   # Start export
   export_node(notebook, output_dir)
   print(f"Export complete: {output_dir}")

**Key Points:**

* Recursively traverse the entire notebook tree
* Preserve directory structure in export
* Download all attachments to disk

Workflow 8: Organize Research Data
-----------------------------------

**Scenario:** Create a standardized directory structure for a research study.

.. code-block:: python

   from labapi import Client, Index
   from io import BytesIO
   import json

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[0]

   # Create study structure
   study = notebook.create_directory("Research Study 2024")

   # Create methodology directory
   method1 = study.create_directory("method_1")

   # Add method metadata
   method_meta = method1.create_page("meta.json")
   method_meta.entries.create_json_entry({
       "name": "Method 1: Behavioral Assessment",
       "description": "Standard behavioral assessment protocol"
   })

   # Create subjects directory
   subjects = method1.create_directory("subjects")

   # Create 5 subject directories with metadata
   for i in range(1, 6):
       subj = subjects.create_directory(f"subj_{i}")

       # Subject metadata
       subj_meta = subj.create_page("meta.json")
       subj_meta.entries.create_json_entry({
           "id": f"SUBJ-{i:03d}",
           "gender": "male" if i % 2 == 0 else "female",
           "age": 20 + i
       })

       # Create sessions directory
       sessions = subj.create_directory("sessions")

       # Create first session with notes
       sess1 = sessions.create_directory("1")
       notes = sess1.create_page("notes.txt")
       notes.entries.create_entry(
           "plain text entry",
           "Session 1 - Baseline assessment"
       )

       print(f"Created subject {i} structure")

   print("Research study structure created")

**Key Points:**

* Create standardized structures programmatically
* Use loops to generate consistent directories
* Add metadata to each organizational level

What's Next?
------------

* :doc:`json-pattern` - Deep dive into the dual-entry JSON pattern
* :doc:`troubleshooting` - Common issues and solutions
* :doc:`navigation` - Advanced navigation techniques
