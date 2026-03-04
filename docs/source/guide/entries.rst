.. _entries:

Working with Entries
====================

Entries are the fundamental building blocks of a LabArchives page. They contain the actual data, such as rich text, plain text, headers, file attachments, and widgets.

Accessing Entries
-----------------

You can access the entries of a :class:`~labapi.tree.page.NotebookPage` through its ``entries`` property. This property returns an :class:`~labapi.entry.collection.Entries` object, which behaves like a sequence.

.. code-block:: python

   page = notebook.traverse("Project A/Experiment 1/Results")
   
   # Get the number of entries
   print(len(page.entries))
   
   # Iterate over entries
   for entry in page.entries:
       print(f"ID: {entry.id}, Type: {entry.content_type}")
   
   # Access an entry by index
   first_entry = page.entries[0]

Entry Types
-----------

LabArchives supports several entry types. In ``labapi``, each type is represented by a specific class inheriting from :class:`~labapi.entry.entries.base.Entry`.

Text-based Entries
~~~~~~~~~~~~~~~~~~

Text-based entries store their content as strings.

* **Rich Text Entry** (:class:`~labapi.entry.entries.text.TextEntry`): Used for formatted text, typically HTML. Content type: ``"text entry"``.
* **Plain Text Entry** (:class:`~labapi.entry.entries.text.PlainTextEntry`): Used for unformatted, raw text. Content type: ``"plain text entry"``.
* **Header Entry** (:class:`~labapi.entry.entries.text.HeaderEntry`): Used for headings or titles within a page. Content type: ``"heading"``.

.. code-block:: python

   # Accessing text content
   text_entry = page.entries[0]
   print(text_entry.content)
   
   # Updating text content
   text_entry.content = "<p>Updated rich text content</p>"

Attachment Entries
~~~~~~~~~~~~~~~~~~

Attachment entries (:class:`~labapi.entry.entries.attachment.AttachmentEntry`) represent file attachments. Their content is an :class:`~labapi.entry.attachment.Attachment` object.

.. code-block:: python

   attachment_entry = page.entries[1]
   attachment = attachment_entry.content
   
   print(f"Filename: {attachment.filename}")
   print(f"MIME Type: {attachment.mime_type}")
   print(f"Caption: {attachment.caption}")
   
   # Read the file data
   data = attachment.read()

Widget Entries
~~~~~~~~~~~~~~

Widget entries (:class:`~labapi.entry.entries.widget.WidgetEntry`) embed interactive content or external applications. Like text entries, their content is represented as a string (often JSON or HTML).

.. note::
   Widget entries are currently read-only in ``labapi``. Their ``content`` property returns the widget's internal data as a JSON-formatted string.

Creating New Entries
--------------------

You can create new entries using the :meth:`~labapi.entry.collection.Entries.create_entry` method.

.. code-block:: python

   # Create a rich text entry
   page.entries.create_entry("text entry", "<h1>New Section</h1><p>Some content...</p>")
   
   # Create a heading
   page.entries.create_entry("heading", "Experiment Notes")
   
   # Create a plain text entry
   page.entries.create_entry("plain text entry", "Raw data string")

Creating Attachments
~~~~~~~~~~~~~~~~~~~~

To create an attachment entry, you first need to create an :class:`~labapi.entry.attachment.Attachment` object.

.. code-block:: python

   from io import BytesIO
   from labapi.entry import Attachment
   
   # Create attachment from in-memory data
   data = BytesIO(b"Hello, LabArchives!")
   attachment = Attachment(data, "text/plain", "hello.txt", "A simple text file")
   
   # Upload as a new entry
   page.entries.create_entry("attachment", attachment)

You can also create an attachment directly from a file on disk:

.. code-block:: python

   with open("data.csv", "rb") as f:
       attachment = Attachment.from_file(f)
       page.entries.create_entry("attachment", attachment)

Working with JSON Data
----------------------

A common pattern is to store structured data as a JSON attachment with a formatted preview in a companion text entry. The :meth:`~labapi.entry.collection.Entries.create_json_entry` method simplifies this.

.. code-block:: python

   data = {
       "experiment_id": "EXP-123",
       "results": [1.2, 3.4, 5.6],
       "status": "complete"
   }
   
   # Creates both an attachment entry and a text entry preview
   file_entry, text_entry = page.entries.create_json_entry(data)

Modifying Entries
-----------------

To modify an entry, simply set its ``content`` property. The change is automatically synchronized with the LabArchives server.

.. code-block:: python

   entry = page.entries[0]
   entry.content = "New content for the entry"

For attachments, setting the ``content`` property with a new :class:`~labapi.entry.attachment.Attachment` object will update the file.

.. code-block:: python

   with open("updated_data.csv", "rb") as f:
       new_attachment = Attachment.from_file(f)
       attachment_entry.content = new_attachment