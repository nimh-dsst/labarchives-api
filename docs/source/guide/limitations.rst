.. _limitations:

Capabilities and Limitations
============================

This page summarizes the current scope of ``labapi`` in one place so you can plan around known boundaries.
It applies to the current documentation set and reflects behavior verified at the time of writing.

Current Capabilities
--------------------

``labapi`` currently supports the following common workflows well:

* Navigating notebooks, directories, and pages by path or index.
* Creating and editing text entries (rich text, plain text, and headers).
* Uploading and updating attachment entries.
* Copying pages and directories for supported entry types.
* Refreshing cached tree/page state when collaborating across sessions.

Known Limitations and Caveats
-----------------------------

Unsupported entry types are wrapped as ``UnknownEntry``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a page contains entry types that ``labapi`` does not model yet, those
entries are wrapped as :class:`~labapi.entry.entries.unknown.UnknownEntry` and
loaded with a warning. This preserves page order and IDs, but editing behavior
is limited for those fallback objects.

Widget entries are read-only
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:class:`~labapi.entry.entries.widget.WidgetEntry` is supported for reading only.
You can inspect widget content, but editing widget content is not currently supported.

Duplicate names return first-match results by default
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Name-based lookup methods such as ``collection["name"]`` and path traversal return the first match when duplicates exist.
To avoid ambiguity, use ID-based lookup or explicit ``Index.Name`` access to retrieve all matches.

Reserved ``".."`` path segments cannot be addressed by name
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Path traversal treats ``".."`` as parent navigation, so nodes literally named ``".."`` cannot be
resolved via :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.traverse`.

``refresh()`` does not update old child references
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After calling ``refresh()``, previously captured child objects (entries/pages/directories) still hold stale cached state.
Re-fetch children from the refreshed parent object instead of reusing old references.

``copy_to()`` has copy fidelity limits and placement restrictions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The copy API has several practical caveats:

* LabArchives may rename attachments during copy.
* Widget and other specialized entry types are not fully supported for copy operations.
* Copy attempts that include unsupported entry types can fail or produce incomplete copies.
* Copying a directory into itself or into one of its descendants raises :class:`ValueError`.

``enumerate_all()`` can return partial results on larger trees
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tree enumeration tracks elapsed wall-clock time (default: about 5 seconds) while traversing children.
When the elapsed-time limit is reached, traversal stops and returns the paths collected so far.
Treat ``enumerate_all()`` results as potentially truncated for very large or slow trees, and prefer smaller
``depth`` values and/or subtree-by-subtree enumeration when completeness matters.

Entry deletion is not available
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deleting individual entries (text, headers, attachments, widgets) is not currently supported by the API client.
Only page and directory deletion/move-to-trash workflows are available.

Attachment update API can return a ``4999`` error
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some attachment update operations can fail with a LabArchives ``4999`` error response.
If this occurs, retrying with a fresh object/session and validating attachment metadata is recommended.

Planning Guidance
-----------------

To reduce surprises in production integrations:

1. Prefer ID-based addressing in automation.
2. Refresh parent nodes before critical reads and then re-fetch child objects.
3. Validate copied content (especially attachments and specialized entries).
4. Treat unsupported entry types and ``4999`` attachment-update failures as expected error-handling cases.

Related Pages
-------------

* :ref:`entries`
* :ref:`index_access`
* :ref:`paths`
* :ref:`clearing_cache`
* :doc:`../quick_start/navigating`
* :doc:`../quick_start/copying`
* :doc:`../quick_start/deleting`
