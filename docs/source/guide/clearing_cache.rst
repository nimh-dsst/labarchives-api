.. _clearing_cache:

Clearing Cache
==============

The LabArchives API client caches various data to improve performance and reduce unnecessary API calls.
However, there are situations where you may need to refresh this cached data to reflect changes made
outside your current session.

Refreshing Object Cache
-----------------------

Tree nodes (notebooks, directories, and pages) provide a :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.refresh`
method that clears cached data and forces the object to re-fetch from the API on next access.

Refreshing a Page
~~~~~~~~~~~~~~~~~

When you refresh a page, the cached entries are cleared:

.. code-block:: python

    # Get a page
    page = notebook.traverse("My Folder/My Page")

    # Work with entries
    entries = page.entries  # Fetches from API and caches

    # Some time later, you want to see if new entries were added
    page.refresh()

    # Next access will fetch fresh data from the API
    entries = page.entries  # Re-fetches from API

Refreshing a Directory or Notebook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Similarly, you can refresh directories and notebooks to reload their children:

.. code-block:: python

    # Get a directory
    directory = notebook.traverse("My Folder")

    # Access children
    children = directory.children  # Fetches and caches

    # Refresh to see if new pages/subdirectories were added
    directory.refresh()

    # Next access gets fresh data
    children = directory.children  # Re-fetches from API

When You Usually Do Not Need Refresh
-----------------------------------

If you create, rename, move, or delete nodes through this client, the in-memory tree is updated immediately as part of the same operation. In those cases, you usually do not need to call ``refresh()`` just to observe your own change locally.

This includes:

* ``create()`` appending a new page or directory to the parent container
* ``node.name = "..."`` updating the current object's name in memory after the API call
* ``move_to()`` updating the node's parent and both containers' child lists
* ``delete()`` renaming and moving the current node into ``API Deleted Items``

.. code-block:: python

    from labapi import NotebookDirectory, NotebookPage

    archive = notebook.create(NotebookDirectory, "Archive")
    page = notebook.create(NotebookPage, "Fresh Results")

    print("Fresh Results" in list(notebook))

    page.move_to(archive)
    print(page.parent is archive)  # True without refresh()

Use ``refresh()`` when you need to pick up changes made outside the current object graph, such as edits from another user, the web UI, or a separate API session.

When to Refresh Data
--------------------

You typically need to refresh cached data in these scenarios:

1. **Collaborative environments**: When other users or processes may be modifying the notebook
2. **Long-running scripts**: When your script runs for an extended period and you want to check for updates
3. **After external changes**: When you've made changes through the web interface or another API session
4. **Polling for changes**: When waiting for external processes to create or modify content

Example: Polling for New Entries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    import time

    page = notebook.traverse("Experiment Results")

    while True:
        # Clear cache and check for new entries
        page.refresh()
        entries = page.entries

        print(f"Current entry count: {len(entries)}")

        if len(entries) >= 10:
            print("Required entries found!")
            break

        time.sleep(30)  # Wait 30 seconds before checking again

Important Limitations
---------------------

.. warning::
    The current implementation of ``refresh()`` has some limitations:

    **Stale object references**: If you have stored references to child objects (pages, directories,
    or entries) before calling ``refresh()``, those objects will **not** be automatically updated.
    They will continue to use their old cached data.

    **Example of potential issue:**

    .. code-block:: python

        page = notebook.traverse("My Page")
        entry = page.entries[0]  # Get reference to first entry

        # Refresh the page
        page.refresh()

        # This entry object still has old cached data!
        # It wasn't invalidated by the refresh
        print(entry.content)  # May show stale data

    **Best practice**: After calling ``refresh()``, re-fetch any child objects you need
    instead of reusing old references:

    .. code-block:: python

        page = notebook.traverse("My Page")

        # Refresh and re-fetch entries
        page.refresh()
        entry = page.entries[0]  # Get a fresh reference

        print(entry.content)  # Shows current data

What Gets Cached
----------------

The following data is cached and will be cleared by ``refresh()``:

**For notebooks and directories:**

* List of child pages and subdirectories
* Child count

**For pages:**

* List of entries on the page
* Entry content and metadata

**Not cached (always fresh from API):**

* User authentication state
* Notebook metadata accessed through :class:`~labapi.user.User`
