Making Arbitrary API Calls
==========================

While ``labapi`` provides high-level objects like :class:`~labapi.tree.notebook.Notebook` and :class:`~labapi.entry.entries.base.Entry`, you may sometimes need to call LabArchives API endpoints that are not yet fully wrapped by the library.

Using the User Object
---------------------

The easiest way to make arbitrary calls is through the :class:`~labapi.user.User` object. Its :meth:`~labapi.user.User.api_get` and :meth:`~labapi.user.User.api_post` methods automatically include your User ID (``uid``) and handle request signing.

.. code-block:: python

   # Get information about a specific notebook using its ID
   xml_response = user.api_get("notebooks/notebook_info", nbid="12345.6")

   # The result is an lxml Element object
   print(xml_response.tag)  # Output: notebooks

Parsing XML Responses
---------------------

Since the LabArchives API returns XML, ``labapi`` uses the ``lxml`` library for parsing. You can use standard ``lxml`` methods or the built-in :func:`~labapi.util.extract.extract_etree` utility for simpler data extraction.

Using extract_etree
~~~~~~~~~~~~~~~~~~

The :func:`~labapi.util.extract.extract_etree` function allows you to define a "format dictionary" that maps XML tags to Python types or nested structures.

.. code-block:: python

   from labapi.util.extract import extract_etree, to_bool

   # Define what we want to extract from the <notebook> element
   format_dict = {
       "notebook": {
           "name": str,
           "id": str,
           "is-student": to_bool,
           "signing": str
       }
   }

   data = extract_etree(xml_response, format_dict)
   
   print(f"Notebook Name: {data['name']}")
   print(f"Is Student: {data['is-student']}")

Raw and Streaming Responses
---------------------------

For more control, or when dealing with non-XML data, you can use the :class:`~labapi.client.Client` methods directly.

Raw Responses
~~~~~~~~~~~~~

If you need access to HTTP headers or the raw response body, use :meth:`~labapi.client.Client.raw_api_get` or :meth:`~labapi.client.Client.raw_api_post`. These return a standard :class:`requests.Response` object.

.. code-block:: python

   response = user.client.raw_api_get("users/max_file_size", uid=user.id)
   print(response.status_code)
   print(response.headers['Content-Type'])

Streaming Data
~~~~~~~~~~~~~~

For downloading large attachments or processing responses incrementally, use the streaming methods :meth:`~labapi.client.Client.stream_api_get` or :meth:`~labapi.client.Client.stream_api_post`. These return a generator that yields chunks of bytes.

.. code-block:: python

   # Downloading a large file manually
   with open("large_file.zip", "wb") as f:
       for chunk in user.client.stream_api_get("entries/entry_attachment", uid=user.id, eid="987.6"):
           f.write(chunk)

Constructing Signed URLs
------------------------

If you need to generate a signed URL to be used elsewhere (e.g., in a web browser or a different tool), use :meth:`~labapi.client.Client.construct_url`.

.. code-block:: python

   # Generate a URL that expires in 10 minutes
   from datetime import timedelta
   
   url = user.client.construct_url(
       "entries/entry_attachment",
       query={"uid": user.id, "eid": "987.6"},
       expires_in=timedelta(minutes=10)
   )
   print(url)
