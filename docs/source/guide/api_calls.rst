.. _api_calls:

Making Arbitrary API Calls
==========================

Use this page when you need a LabArchives endpoint that does not yet have a
high-level wrapper in ``labapi``. The examples below assume you already have an
authenticated ``user`` object; see :ref:`first_calls` or :ref:`auth` if you
need to establish a session first.

Choose an API Access Level
--------------------------

.. list-table::
   :header-rows: 1

   * - Need
     - Use
     - Returns
   * - Signed request with ``uid`` added automatically
     - ``user.api_get()`` / ``user.api_post()``
     - Parsed XML as an ``lxml`` element
   * - Raw response headers and body
     - ``user.client.raw_api_get()`` / ``raw_api_post()``
     - :class:`requests.Response`
   * - Streaming large responses
     - ``user.client.stream_api_get()`` / ``stream_api_post()``
     - :class:`labapi.client.StreamingResponse`
   * - A signed URL for another tool
     - ``user.client.construct_url()``
     - A URL string

Use the User Object
-------------------

The easiest way to make arbitrary calls is through
:class:`~labapi.user.User`. Its
:meth:`~labapi.user.User.api_get` and
:meth:`~labapi.user.User.api_post` methods automatically include your User ID
(``uid``) and handle request signing.

.. code-block:: python

   xml_response = user.api_get("notebooks/notebook_info", nbid="12345.6")
   print(xml_response.tag)

Parsing XML Responses
---------------------

Because the LabArchives API returns XML, ``labapi`` uses ``lxml`` for parsing.
You can work with the returned element directly or use
:func:`~labapi.util.extract.extract_etree` for structured extraction.

Using ``extract_etree``
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from labapi.util import extract_etree, to_bool

   format_dict = {
       "notebook": {
           "name": str,
           "id": str,
           "is-student": to_bool,
           "signing": str,
       }
   }

   data = extract_etree(xml_response, format_dict)

   print(f"Notebook Name: {data['name']}")
   print(f"Is Student: {data['is-student']}")

Raw and Streaming Responses
---------------------------

For more control, or when dealing with non-XML data, use the lower-level
:class:`~labapi.client.Client` methods directly.

Raw Responses
~~~~~~~~~~~~~

If you need HTTP headers or the raw response body, use
:meth:`~labapi.client.Client.raw_api_get` or
:meth:`~labapi.client.Client.raw_api_post`:

.. code-block:: python

   response = user.client.raw_api_get("users/max_file_size", uid=user.id)
   print(response.status_code)
   print(response.headers["Content-Type"])

Streaming Data
~~~~~~~~~~~~~~

For large attachments or incremental processing, use the streaming methods.
They return a :class:`~labapi.client.StreamingResponse`, which is both
iterable and a context manager:

.. code-block:: python

   with (
       user.client.stream_api_get(
           "entries/entry_attachment",
           uid=user.id,
           eid="987.6",
       ) as stream,
       open("large_file.zip", "wb") as f,
   ):
       for chunk in stream:
           f.write(chunk)

Constructing Signed URLs
------------------------

Use :meth:`~labapi.client.Client.construct_url` when you need a signed URL for
another tool, such as a browser download or a service-to-service handoff.

.. code-block:: python

   from datetime import timedelta

   url = user.client.construct_url(
       "entries/entry_attachment",
       query={"uid": user.id, "eid": "987.6"},
       expires_in=timedelta(minutes=10),
   )
   print(url)

Related Pages
-------------

- :ref:`auth` for the authentication flows that produce a ``user`` object.
- :ref:`first_calls` for the setup pattern used in the snippets above.
- :ref:`reference` for the generated client and user API signatures.
