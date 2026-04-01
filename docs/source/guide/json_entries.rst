.. _json_entries:

JSON Entries
============

``labapi`` provides a high-level way to store JSON data so it is both
machine-readable and easy to inspect in the LabArchives UI.

How JSON Entries Are Stored
---------------------------

When you create a JSON entry with ``labapi``, the library creates two related
records:

- A JSON attachment that preserves the original structured data exactly.
- A rich-text preview entry that shows a formatted, human-readable version in
  the notebook page.

This pairing makes it easy to keep a reliable machine format without giving up
on readable notebook content.

Create a JSON Entry
-------------------

Use :meth:`~labapi.entry.collection.Entries.create_json_entry` on
``page.entries``:

.. code-block:: python

   from labapi import JsonData

   page = user.notebooks["My Notebook"].traverse("My Json Data/Page 1")

   my_data: JsonData = {
       "name": "Experiment 1",
       "date": "2024-01-01",
       "readings": [
           {"time": "10:00", "value": 1.23},
           {"time": "11:00", "value": 4.56},
       ],
       "completed": True,
   }

   attachment_entry, text_entry = page.entries.create_json_entry(my_data)

   print(f"Created attachment entry (ID: {attachment_entry.id})")
   print(f"Created text preview (ID: {text_entry.id})")

What You Get Back
-----------------

:meth:`~labapi.entry.collection.Entries.create_json_entry` returns both created
entry objects:

- ``attachment_entry`` for the uploaded ``.json`` attachment.
- ``text_entry`` for the pretty-printed preview shown on the page.

Related Pages
-------------

- :ref:`entries` for the surrounding entry model.
- :doc:`/examples/json_sync` for a complete JSON sync workflow.
- :ref:`limitations` for current capability boundaries.
