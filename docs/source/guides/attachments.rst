Working with Attachments
=========================

This tutorial covers uploading, downloading, and managing file attachments in LabArchives using **labapi**.

Prerequisites
-------------

* Authenticated user session (see :doc:`quickstart`)
* Basic knowledge of creating pages (see :doc:`creating-content`)

The Attachment Class
---------------------

The ``Attachment`` class represents a file with metadata:

* **backing** - File-like object (BytesIO, file handle)
* **mime_type** - MIME type (e.g., "text/csv", "image/png")
* **filename** - Name of the file
* **caption** - Optional description

Upload Files
------------

Upload from Disk
~~~~~~~~~~~~~~~~

The easiest way to upload a file:

.. code-block:: python

   from labapi import Attachment

   # Create a page for the attachment
   page = directory.create_page("Data Files")

   # Upload from disk
   with open("experiment_data.csv", "rb") as f:
       attachment = Attachment.from_file(f)
       page.entries.create_entry("attachment", attachment)

The ``from_file()`` method automatically detects the MIME type and filename.

Upload from Bytes
~~~~~~~~~~~~~~~~~

Create attachments from in-memory data:

.. code-block:: python

   from io import BytesIO

   # CSV data as bytes
   csv_data = b"Sample,Value,Unit\nA,1.5,mg\nB,2.3,mg\n"

   attachment = Attachment(
       backing=BytesIO(csv_data),
       mime_type="text/csv",
       filename="results.csv",
       caption="Experiment results"
   )

   page.entries.create_entry("attachment", attachment)

Upload JSON Data
~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from io import BytesIO

   data = {
       "experiment_id": "EXP-001",
       "temperature": 25.5,
       "pressure": 101.3
   }

   json_bytes = json.dumps(data, indent=2).encode("utf-8")
   attachment = Attachment(
       backing=BytesIO(json_bytes),
       mime_type="application/json",
       filename="metadata.json",
       caption="Experimental parameters"
   )

   page.entries.create_entry("attachment", attachment)

Upload Images
~~~~~~~~~~~~~

.. code-block:: python

   # From file
   with open("graph.png", "rb") as f:
       image = Attachment.from_file(f)
       page.entries.create_entry("attachment", image)

   # From bytes (e.g., generated plot)
   import matplotlib.pyplot as plt
   from io import BytesIO

   # Create plot
   plt.plot([1, 2, 3], [4, 5, 6])

   # Save to BytesIO
   img_buffer = BytesIO()
   plt.savefig(img_buffer, format="png")
   img_buffer.seek(0)

   # Upload
   attachment = Attachment(
       backing=img_buffer,
       mime_type="image/png",
       filename="plot.png",
       caption="Data visualization"
   )
   page.entries.create_entry("attachment", attachment)

Download Files
--------------

Find and Download Attachments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import AttachmentEntry, Index

   # Find a page with attachments
   page = notebook[Index.Name : "Results"][0]

   # Iterate through entries
   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content

           print(f"Found: {attachment.filename}")
           print(f"  Type: {attachment.mime_type}")
           print(f"  Size: {attachment.size} bytes")

           # Download the file
           data = attachment.read()

           # Save to disk
           with open(attachment.filename, "wb") as f:
               f.write(data)

Download and Process Text Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi import AttachmentEntry

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content

           # Check if it's a text file
           if attachment.mime_type.startswith("text/"):
               # Read and decode
               text_data = attachment.read().decode("utf-8")
               print(f"Content of {attachment.filename}:")
               print(text_data)

Download and Parse JSON
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from labapi import AttachmentEntry

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content

           if attachment.filename.endswith(".json"):
               # Read and parse JSON
               json_data = attachment.read()
               data = json.loads(json_data)

               print(f"Parsed {attachment.filename}:")
               print(data)

Download and Parse CSV
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import csv
   from io import StringIO
   from labapi import AttachmentEntry

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content

           if attachment.mime_type == "text/csv":
               # Read and parse CSV
               csv_data = attachment.read().decode("utf-8")
               reader = csv.DictReader(StringIO(csv_data))

               print(f"CSV data from {attachment.filename}:")
               for row in reader:
                   print(row)

Update Attachments
------------------

Replace File Contents
~~~~~~~~~~~~~~~~~~~~~

Update an existing attachment entry:

.. code-block:: python

   from labapi import AttachmentEntry, Attachment
   from io import BytesIO

   # Find the attachment entry
   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           if entry.content.filename == "metadata.json":
               # Create new content
               new_data = {"updated": True, "version": 2}
               new_json = json.dumps(new_data).encode()

               # Replace the attachment
               new_attachment = Attachment(
                   backing=BytesIO(new_json),
                   mime_type="application/json",
                   filename=entry.content.filename,
                   caption="Updated metadata"
               )
               entry.content = new_attachment
               break

Batch Upload Files
------------------

Upload multiple files from a directory:

.. code-block:: python

   from pathlib import Path
   from labapi import Attachment

   # Create a page for batch upload
   upload_page = directory.create_page("Batch Upload")

   # Upload all CSV files from a directory
   data_dir = Path("./experiment_data")
   for file_path in data_dir.glob("*.csv"):
       with open(file_path, "rb") as f:
           attachment = Attachment.from_file(f)
           upload_page.entries.create_entry("attachment", attachment)
       print(f"Uploaded: {file_path.name}")

Batch Download Files
--------------------

Download all attachments from a page:

.. code-block:: python

   from labapi import AttachmentEntry
   from pathlib import Path

   # Create output directory
   output_dir = Path("./downloads")
   output_dir.mkdir(exist_ok=True)

   # Download all attachments
   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content
           data = attachment.read()

           # Save to file
           output_path = output_dir / attachment.filename
           with open(output_path, "wb") as f:
               f.write(data)

           print(f"Downloaded: {attachment.filename}")

Working with Large Files
-------------------------

For large files, process in chunks to avoid memory issues:

.. code-block:: python

   from labapi import AttachmentEntry

   for entry in page.entries:
       if isinstance(entry, AttachmentEntry):
           attachment = entry.content

           # Check size before downloading
           if attachment.size > 100 * 1024 * 1024:  # 100 MB
               print(f"Warning: {attachment.filename} is large ({attachment.size} bytes)")

           # For very large files, you might want to download in chunks
           # (Note: current implementation reads entire file into memory)
           data = attachment.read()

           # Process in chunks
           chunk_size = 1024 * 1024  # 1 MB
           with open(attachment.filename, "wb") as f:
               for i in range(0, len(data), chunk_size):
                   f.write(data[i:i + chunk_size])

Complete Example: Organize Data Files
--------------------------------------

Here's a complete workflow for organizing experimental data files:

.. code-block:: python

   from labapi import Client, Attachment, AttachmentEntry, Index
   from pathlib import Path
   import json

   client = Client()
   user = client.login_authcode(email, auth_code)
   notebook = user.notebooks[0]

   # Create experiment directory structure
   experiments = notebook.create_directory("Experiments")
   exp_001 = experiments.create_directory("EXP-001")

   # Upload metadata
   meta_page = exp_001.create_page("metadata.json")
   metadata = {
       "experiment_id": "EXP-001",
       "date": "2024-02-20",
       "researcher": "Jane Doe"
   }
   meta_attachment = Attachment(
       backing=BytesIO(json.dumps(metadata, indent=2).encode()),
       mime_type="application/json",
       filename="metadata.json",
       caption="Experiment metadata"
   )
   meta_page.entries.create_entry("attachment", meta_attachment)

   # Upload data files
   data_files = ["sample_1.csv", "sample_2.csv", "sample_3.csv"]
   for filename in data_files:
       page = exp_001.create_page(filename)
       with open(f"data/{filename}", "rb") as f:
           attachment = Attachment.from_file(f)
           page.entries.create_entry("attachment", attachment)
       print(f"Uploaded: {filename}")

   # Later: Download and process results
   results_page = exp_001[Index.Name : "sample_1.csv"][0]
   for entry in results_page.entries:
       if isinstance(entry, AttachmentEntry):
           data = entry.content.read().decode("utf-8")
           print(f"Processing {entry.content.filename}:")
           # Process CSV data here
           print(data[:100])

What's Next?
------------

* :doc:`workflows` - Complete real-world workflows
* :doc:`json-pattern` - Learn the dual-entry JSON pattern
* :doc:`navigation` - Advanced navigation techniques
