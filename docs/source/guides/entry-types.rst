Entry Types Reference
=====================

This guide provides a complete reference for all entry types available in **labapi**.

Overview
--------

LabArchives pages contain **entries** - discrete content blocks that can be text, files, or widgets. Each entry type has specific characteristics and use cases.

Entry Type Hierarchy
---------------------

All entries inherit from the base ``Entry`` class:

.. code-block:: text

   Entry (abstract)
   ├── BaseTextEntry (abstract)
   │   ├── TextEntry (rich text/HTML)
   │   ├── PlainTextEntry (unformatted text)
   │   ├── HeaderEntry (headings/titles)
   │   └── WidgetEntry (embedded content)
   └── AttachmentEntry (files)

Text-Based Entries
------------------

All text-based entries inherit from ``BaseTextEntry`` and store their content as strings.

TextEntry (Rich Text)
~~~~~~~~~~~~~~~~~~~~~

**Purpose:** Formatted text with HTML markup

**Content Type:** ``"text entry"``

**Use Cases:**

* Experiment descriptions with formatting
* Reports with bold, italic, lists
* Embedded links and images

**Example:**

.. code-block:: python

   from labapi import TextEntry

   # Create a rich text entry
   html_content = """
   <h2>Experiment Results</h2>
   <p>The experiment was <strong>successful</strong>.</p>
   <ul>
       <li>Temperature: 25°C</li>
       <li>Pressure: 1 atm</li>
       <li>Duration: 2 hours</li>
   </ul>
   """

   page.entries.create_entry("text entry", html_content)

   # Read and modify
   for entry in page.entries:
       if isinstance(entry, TextEntry):
           content = entry.content
           # Update content
           entry.content = "<p>Updated content</p>"

**Supported HTML Tags:**

LabArchives supports a subset of HTML tags:

* Headings: ``<h1>`` to ``<h6>``
* Text formatting: ``<p>``, ``<strong>``, ``<em>``, ``<u>``
* Lists: ``<ul>``, ``<ol>``, ``<li>``
* Links: ``<a href="...">``
* Tables: ``<table>``, ``<tr>``, ``<td>``, ``<th>``
* Divisions: ``<div>``

PlainTextEntry
~~~~~~~~~~~~~~

**Purpose:** Unformatted text content

**Content Type:** ``"plain text entry"``

**Use Cases:**

* Simple notes and comments
* Quick observations
* Plain text data

**Example:**

.. code-block:: python

   from labapi import PlainTextEntry

   # Create a plain text entry
   notes = "Patient fell asleep during test. Session paused at 14:30."
   page.entries.create_entry("plain text entry", notes)

   # Read content
   for entry in page.entries:
       if isinstance(entry, PlainTextEntry):
           print(f"Note: {entry.content}")

**Characteristics:**

* No HTML formatting
* Preserves line breaks
* Faster to create than rich text
* Better for simple annotations

HeaderEntry
~~~~~~~~~~~

**Purpose:** Section headings and titles

**Content Type:** ``"heading"`` (note: not "header")

**Use Cases:**

* Organize page sections
* Create table of contents structure
* Separate different parts of an experiment

**Example:**

.. code-block:: python

   from labapi import HeaderEntry

   # Create section headers
   page.entries.create_entry("header", "Methods")
   page.entries.create_entry("text entry", "<p>Detailed methodology...</p>")

   page.entries.create_entry("header", "Results")
   page.entries.create_entry("text entry", "<p>Experimental results...</p>")

   # Find all headers
   for entry in page.entries:
       if isinstance(entry, HeaderEntry):
           print(f"Section: {entry.content}")

**Characteristics:**

* Appears as large, bold text
* Used for visual organization
* Content is plain text (no HTML)

WidgetEntry
~~~~~~~~~~~

**Purpose:** Embedded interactive content or external applications

**Content Type:** ``"widget entry"``

**Use Cases:**

* Embedded charts or visualizations
* External tool integrations
* Interactive data displays
* JSON data structures

**Example:**

.. code-block:: python

   from labapi import WidgetEntry
   import json

   # Create a widget with JSON data
   widget_data = json.dumps({
       "type": "chart",
       "data": [1, 2, 3, 4, 5]
   })

   page.entries.create_entry("widget entry", widget_data)

   # Read widget content
   for entry in page.entries:
       if isinstance(entry, WidgetEntry):
           data = json.loads(entry.content)
           print(f"Widget: {data['type']}")

**Characteristics:**

* Content is stored as text (often JSON or HTML)
* Can represent complex data structures
* May require special handling in LabArchives UI

File-Based Entries
------------------

AttachmentEntry
~~~~~~~~~~~~~~~

**Purpose:** File attachments of any type

**Content Type:** ``"attachment"``

**Use Cases:**

* Data files (CSV, JSON, Excel)
* Images (PNG, JPG, GIF)
* Documents (PDF, Word, PowerPoint)
* Code files (Python, R, MATLAB)
* Any binary or text file

**Example:**

.. code-block:: python

   from labapi import AttachmentEntry, Attachment
   from io import BytesIO

   # Upload a file
   with open("data.csv", "rb") as f:
       attachment = Attachment.from_file(f)
       page.entries.create_entry("attachment", attachment)

   # Download attachments
   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content
           print(f"File: {attachment.filename}")
           print(f"  Type: {attachment.mime_type}")
           print(f"  Size: {attachment.size} bytes")

           # Download content
           data = attachment.read()

           # Save to disk
           with open(attachment.filename, "wb") as f:
               f.write(data)

**Attachment Properties:**

.. code-block:: python

   attachment = entry.content

   # Available properties
   filename = attachment.filename      # "data.csv"
   mime_type = attachment.mime_type    # "text/csv"
   size = attachment.size              # Size in bytes
   caption = attachment.caption        # Optional description

   # Read file content
   data = attachment.read()  # Returns bytes

**Supported File Types:**

LabArchives accepts virtually any file type:

* **Text:** ``.txt``, ``.csv``, ``.json``, ``.xml``
* **Images:** ``.png``, ``.jpg``, ``.gif``, ``.svg``
* **Documents:** ``.pdf``, ``.docx``, ``.xlsx``, ``.pptx``
* **Code:** ``.py``, ``.r``, ``.m``, ``.ipynb``
* **Archives:** ``.zip``, ``.tar.gz``
* **Video:** ``.mp4``, ``.avi``, ``.mov``

Entry Operations
----------------

Create Entries
~~~~~~~~~~~~~~

Use ``page.entries.create_entry()`` with the content type and data:

.. code-block:: python

   # Text entry
   page.entries.create_entry("text entry", "<p>HTML content</p>")

   # Plain text entry
   page.entries.create_entry("plain text entry", "Plain text")

   # Header
   page.entries.create_entry("header", "Section Title")

   # Widget
   page.entries.create_entry("widget entry", "Widget data")

   # Attachment
   page.entries.create_entry("attachment", attachment_object)

Read Entries
~~~~~~~~~~~~

Iterate through entries and check their type:

.. code-block:: python

   from labapi import TextEntry, PlainTextEntry, AttachmentEntry

   for entry in page.entries:
       print(f"Entry ID: {entry.id}")
       print(f"Type: {type(entry).__name__}")

       if isinstance(entry, TextEntry):
           print(f"HTML: {entry.content[:100]}")
       elif isinstance(entry, PlainTextEntry):
           print(f"Text: {entry.content}")
       elif isinstance(entry, AttachmentEntry):
           print(f"File: {entry.content.filename}")

Update Entries
~~~~~~~~~~~~~~

Modify entry content by setting the ``content`` property:

.. code-block:: python

   from labapi import TextEntry

   for entry in page.entries:
       if isinstance(entry, TextEntry):
           # Update the content
           entry.content = "<p>Updated HTML content</p>"

For attachments, replace with a new ``Attachment`` object:

.. code-block:: python

   from labapi import AttachmentEntry, Attachment
   from io import BytesIO

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           # Create new attachment
           new_data = b"New file content"
           new_attachment = Attachment(
               backing=BytesIO(new_data),
               mime_type="text/plain",
               filename=entry.content.filename,
               caption="Updated file"
           )
           # Replace
           entry.content = new_attachment

Entry Properties
----------------

All entries have these common properties:

.. code-block:: python

   entry.id            # Unique entry identifier (str)
   entry.content       # Entry content (type varies)
   entry.content_type  # Content type string (e.g., "text entry")

Type Checking
~~~~~~~~~~~~~

Use ``isinstance()`` to check entry types:

.. code-block:: python

   from labapi import TextEntry, PlainTextEntry, HeaderEntry
   from labapi import WidgetEntry, AttachmentEntry

   if isinstance(entry, TextEntry):
       # Handle rich text
       pass
   elif isinstance(entry, PlainTextEntry):
       # Handle plain text
       pass
   elif isinstance(entry, HeaderEntry):
       # Handle header
       pass
   elif isinstance(entry, WidgetEntry):
       # Handle widget
       pass
   elif isinstance(entry, AttachmentEntry):
       # Handle attachment
       pass

Content Type Mapping
--------------------

When creating entries, use these content type strings:

================= ======================== ===================
Class             String for create_entry  content_type value
================= ======================== ===================
TextEntry         "text entry"             "text entry"
PlainTextEntry    "plain text entry"       "plain text entry"
HeaderEntry       "header"                 "heading"
WidgetEntry       "widget entry"           "widget entry"
AttachmentEntry   "attachment"             "attachment"
================= ======================== ===================

.. note::
   The string for ``create_entry()`` differs from ``content_type`` for HeaderEntry ("header" vs "heading").

Advanced Patterns
-----------------

Filter by Entry Type
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import AttachmentEntry

   # Get all attachment entries
   attachments = [
       entry for entry in page.entries
       if isinstance(entry, AttachmentEntry)
   ]

   print(f"Found {len(attachments)} attachments")

Count Entry Types
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from collections import Counter

   entry_counts = Counter(
       type(entry).__name__ for entry in page.entries
   )

   print(entry_counts)
   # Counter({'TextEntry': 5, 'AttachmentEntry': 3, 'HeaderEntry': 2})

Find Entry by ID
~~~~~~~~~~~~~~~~

.. code-block:: python

   def find_entry_by_id(page, entry_id):
       """Find an entry by its ID."""
       for entry in page.entries:
           if entry.id == entry_id:
               return entry
       return None

   entry = find_entry_by_id(page, "12345")

Best Practices
--------------

1. **Choose the Right Type**

   * Use ``TextEntry`` for formatted content
   * Use ``PlainTextEntry`` for simple notes
   * Use ``HeaderEntry`` for organization
   * Use ``AttachmentEntry`` for files

2. **Type Checking**

   Always use ``isinstance()`` instead of comparing ``content_type`` strings:

   .. code-block:: python

      # Good
      if isinstance(entry, TextEntry):
          pass

      # Avoid
      if entry.content_type == "text entry":
          pass

3. **Attachment Handling**

   Always read attachment content before using it:

   .. code-block:: python

      data = attachment.read()  # Returns bytes
      text = data.decode('utf-8')  # If it's text

4. **Content Updates**

   Remember that setting ``entry.content`` makes an API call:

   .. code-block:: python

      # This makes one API call
      entry.content = "New content"

      # Avoid multiple updates in a loop
      for i in range(100):
          entry.content = f"Update {i}"  # 100 API calls!

What's Next?
------------

* :doc:`json-pattern` - Learn the dual-entry JSON pattern
* :doc:`attachments` - Working with file attachments
* :doc:`creating-content` - Creating different entry types
