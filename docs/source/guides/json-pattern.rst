The Dual-Entry JSON Pattern
============================

This guide explains the dual-entry JSON pattern used in **labapi** for storing structured data with both raw and human-readable formats.

The Problem
-----------

When storing structured data (JSON) in LabArchives, you face a choice:

1. **Attachment only** - Machine-readable but not visible in the web interface
2. **Text entry only** - Human-readable but hard to parse programmatically

Neither approach is ideal for data that needs to be both viewed and processed.

The Solution: Dual-Entry Pattern
---------------------------------

The dual-entry pattern creates **two linked entries** for JSON data:

1. **AttachmentEntry** - Raw JSON file (machine-readable)
2. **TextEntry** - Formatted preview (human-readable)

This gives you:

* ✓ Raw JSON for programmatic access
* ✓ Formatted preview in the LabArchives web interface
* ✓ Reference links between entries

How It Works
------------

The ``create_json_entry()`` Method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library provides a convenience method for creating dual entries:

.. code-block:: python

   from labapi import Client

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[0]

   # Create a page for metadata
   page = notebook.create_page("metadata.json")

   # Create dual-entry JSON
   data = {
       "experiment_id": "EXP-001",
       "date": "2024-02-20",
       "researcher": "Jane Doe",
       "temperature": 25.5,
       "pressure": 101.3
   }

   attachment_entry, text_entry = page.entries.create_json_entry(data)

This creates:

1. An attachment named ``uploaded_data_<timestamp>.json`` with the raw JSON
2. A text entry with a formatted preview

What Gets Created
~~~~~~~~~~~~~~~~~

**Attachment Entry:**

* **Filename:** ``uploaded_data_1708435200.json``
* **MIME Type:** ``application/json``
* **Caption:** ``"Uploaded JSON file"``
* **Content:** Raw JSON bytes

**Text Entry:**

* **Content Type:** ``text entry``
* **Content:** HTML with reference and formatted JSON

.. code-block:: html

   <p>Reference Attachment: uploaded_data_1708435200.json</p>
   <p>Entry ID: 12345</p>
   <pre>
   {
       "experiment_id": "EXP-001",
       "date": "2024-02-20",
       "researcher": "Jane Doe",
       "temperature": 25.5,
       "pressure": 101.3
   }
   </pre>

The text entry includes:

* Filename of the raw attachment
* Entry ID for programmatic access
* Formatted JSON in a ``<pre>`` block for readability

Reading Dual-Entry JSON
------------------------

Find Both Entries
~~~~~~~~~~~~~~~~~

When reading back, you need to identify both entries:

.. code-block:: python

   from labapi import AttachmentEntry, TextEntry, Index

   # Find the page
   page = notebook[Index.Name : "metadata.json"][0]

   # Separate the two entries
   attachment_entry = None
   text_entry = None

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment_entry = entry
       elif isinstance(entry, TextEntry):
           text_entry = entry

   if not attachment_entry or not text_entry:
       raise ValueError("Dual-entry JSON not found")

Read Raw JSON
~~~~~~~~~~~~~

Access the structured data from the attachment:

.. code-block:: python

   import json

   # Read the raw JSON
   json_bytes = attachment_entry.content.read()
   data = json.loads(json_bytes)

   print(data["experiment_id"])  # "EXP-001"
   print(data["temperature"])    # 25.5

Read Preview
~~~~~~~~~~~~

The text entry contains the human-readable preview:

.. code-block:: python

   # Get the formatted preview
   preview_html = text_entry.content

   # Extract the entry ID reference if needed
   if "Entry ID:" in preview_html:
       # Parse the HTML to get the ID
       import re
       match = re.search(r'Entry ID: (\d+)', preview_html)
       if match:
           referenced_id = match.group(1)
           print(f"References entry: {referenced_id}")

Updating Dual-Entry JSON
-------------------------

To update JSON data, you must update **both entries** to keep them synchronized:

.. code-block:: python

   import json
   from io import BytesIO
   from labapi import Attachment

   # Updated data
   new_data = {
       "experiment_id": "EXP-001",
       "date": "2024-02-20",
       "researcher": "Jane Doe",
       "temperature": 26.0,  # Updated
       "pressure": 101.3,
       "notes": "Temperature increased"  # Added
   }

   # 1. Update the raw attachment
   json_bytes = json.dumps(new_data).encode("utf-8")
   new_attachment = Attachment(
       backing=BytesIO(json_bytes),
       mime_type="application/json",
       filename=attachment_entry.content.filename,  # Keep same filename
       caption="Updated metadata"
   )
   attachment_entry.content = new_attachment

   # 2. Update the text preview
   text_entry.content = f"""
   <p>Reference Attachment: {attachment_entry.content.filename}</p>
   <p>Entry ID: {attachment_entry.id}</p>
   <pre>
   {json.dumps(new_data, indent=4)}
   </pre>
   """

   print("Both entries updated and synchronized")

Complete Example: Experiment Metadata
--------------------------------------

Here's a complete workflow using the dual-entry pattern:

.. code-block:: python

   from labapi import Client, Index, AttachmentEntry, TextEntry
   from io import BytesIO
   import json

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[0]

   # Create experiment structure
   experiment = notebook.create_directory("EXP-001")

   # Create metadata page
   meta_page = experiment.create_page("metadata.json")

   # Initial metadata
   metadata = {
       "experiment_id": "EXP-001",
       "title": "Temperature Effects Study",
       "researcher": "Dr. Smith",
       "start_date": "2024-02-20",
       "status": "active",
       "parameters": {
           "temperature": 25.0,
           "pressure": 101.3,
           "duration_hours": 24
       }
   }

   # Create dual-entry JSON
   attachment_entry, text_entry = meta_page.entries.create_json_entry(metadata)

   print(f"Created metadata with entries:")
   print(f"  Attachment: {attachment_entry.id}")
   print(f"  Text preview: {text_entry.id}")

   # Later: Read and update metadata
   meta_page = experiment[Index.Name : "metadata.json"][0]

   # Find the attachment entry
   for entry in meta_page.entries:
       if isinstance(entry, AttachmentEntry):
           # Read current metadata
           current_data = json.loads(entry.content.read())

           # Update status
           current_data["status"] = "completed"
           current_data["end_date"] = "2024-02-21"

           # Save updated metadata
           new_json = json.dumps(current_data).encode()
           entry.content = Attachment(
               backing=BytesIO(new_json),
               mime_type="application/json",
               filename=entry.content.filename,
               caption="Updated metadata"
           )

           print("Metadata updated")
           break

When to Use the Dual-Entry Pattern
-----------------------------------

**Use dual-entry JSON when:**

* Data needs to be both viewed and processed
* Metadata describes experiments or datasets
* Configuration files should be human-readable
* Structured data needs version history
* Users need to see data in the web interface

**Don't use dual-entry JSON when:**

* Data is purely for programmatic access
* Files are very large (use attachment only)
* Data doesn't need a preview
* Simple key-value pairs (use plain text)

Best Practices
--------------

1. **Keep Entries Synchronized**

   Always update both entries when data changes:

   .. code-block:: python

      # Update attachment
      attachment_entry.content = new_attachment

      # Update preview to match
      text_entry.content = format_preview(new_data)

2. **Use Descriptive Page Names**

   Name pages after their content:

   .. code-block:: python

      meta_page = directory.create_page("metadata.json")
      config_page = directory.create_page("config.json")

3. **Validate JSON Before Saving**

   Ensure data is valid JSON:

   .. code-block:: python

      import json

      try:
          json.dumps(data)  # Validate
          page.entries.create_json_entry(data)
      except (TypeError, ValueError) as e:
          print(f"Invalid JSON: {e}")

4. **Include Timestamps**

   Add timestamps to track when data was created/modified:

   .. code-block:: python

      from datetime import datetime

      data = {
          "created_at": datetime.now().isoformat(),
          "modified_at": datetime.now().isoformat(),
          "data": { ... }
      }

5. **Reference Between Entries**

   The text entry includes the attachment entry ID:

   .. code-block:: python

      # Extract reference ID from preview
      import re
      match = re.search(r'Entry ID: (\w+)', text_entry.content)
      if match:
           attachment_id = match.group(1)

Implementation Details
----------------------

Filename Generation
~~~~~~~~~~~~~~~~~~~

The attachment filename includes a timestamp to ensure uniqueness:

.. code-block:: python

   from datetime import datetime

   filename = f"uploaded_data_{datetime.now().timestamp():.0f}.json"
   # Example: uploaded_data_1708435200.json

This prevents collisions when multiple JSON entries are created on the same page.

JSON Formatting
~~~~~~~~~~~~~~~

The preview uses ``json.dumps()`` with ``indent=4`` for readability:

.. code-block:: python

   import json

   formatted = json.dumps(data, indent=4)

This creates nicely formatted JSON in the text preview.

Alternatives to Dual-Entry
---------------------------

Attachment Only
~~~~~~~~~~~~~~~

For pure data storage without preview:

.. code-block:: python

   with open("data.json", "rb") as f:
       attachment = Attachment.from_file(f)
       page.entries.create_entry("attachment", attachment)

Text Only
~~~~~~~~~

For display-only JSON (not meant to be parsed):

.. code-block:: python

   import json

   preview = f"<pre>{json.dumps(data, indent=2)}</pre>"
   page.entries.create_entry("text entry", preview)

Widget Entry
~~~~~~~~~~~~

For interactive JSON visualization:

.. code-block:: python

   import json

   widget_data = json.dumps(data)
   page.entries.create_entry("widget entry", widget_data)

What's Next?
------------

* :doc:`entry-types` - Complete reference for all entry types
* :doc:`workflows` - See dual-entry pattern in real workflows
* :doc:`attachments` - Working with attachments
