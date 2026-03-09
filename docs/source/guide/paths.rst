.. _paths:

Working with Paths
==================

Paths provide a way to navigate, reference, and create nodes in the notebook tree using Unix-style
slash-separated strings. This is an alternative to chained index access and is especially useful
when working with deeply nested structures.

.. code-block:: python

    # Index access (chained)
    page = notebook["Experiments"]["2024"]["Results"]

    # Path-based (equivalent)
    page = notebook.traverse("Experiments/2024/Results")

Traversing the Tree
-------------------

The :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.traverse` method is available on any tree node
and accepts a slash-separated path string.

.. code-block:: python

    folder = notebook.traverse("Experiments")
    page = notebook.traverse("Experiments/2024/Results")

Absolute vs Relative Paths
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Paths starting with ``/`` are **absolute** -- they are resolved from the notebook root regardless
of where you call ``traverse``.

.. code-block:: python

    # Relative: resolved from `folder`
    page = folder.traverse("2024/Results")

    # Absolute: always resolved from the notebook root
    page = folder.traverse("/Experiments/2024/Results")

Parent Navigation
~~~~~~~~~~~~~~~~~

Use ``..`` to navigate to the parent container.

.. code-block:: python

    parent = page.traverse("..")
    grandparent = page.traverse("../..")

.. note::
   When multiple children share the same name, ``traverse`` returns the first match. Use
   :ref:`index_access` with ``Index.Name`` to retrieve all matches.

.. warning::
   Nodes with the literal name ``".."`` cannot be accessed via ``traverse``, as ``..`` is
   reserved for parent navigation.

Enumerating Descendants
-----------------------

The enumeration methods return relative path strings for all descendants, up to a specified depth.
This is useful for listing or searching the tree without fetching every node individually.

.. code-block:: python

    # All descendants (directories and pages), depth 1 (default)
    notebook.enumerate_all()
    # e.g. ["Experiments", "Experiments/2024", "Protocols"]

    # Only directories
    notebook.enumerate_dirs(max_depth=2)

    # Only pages
    notebook.enumerate_pages(max_depth=2)

``max_depth`` defaults to ``1`` (immediate children only). To fetch the full tree you can increase
it, but be aware that this makes one API request per directory level visited.

.. code-block:: python

    # Enumerate up to 3 levels deep
    all_paths = notebook.enumerate_all(max_depth=3)

    for path in all_paths:
        node = notebook.traverse(path)
        print(path, "->", node.id)

Creating Nodes with Paths
-------------------------

The :meth:`~labapi.tree.mixins.AbstractTreeContainer.create` method accepts a path string (or
:class:`~labapi.util.path.NotebookPath`) as the ``name`` argument. When a multi-segment path is
provided, you must pass ``parents=True`` to allow intermediate directories to be created
automatically.

.. code-block:: python

    from labapi import NotebookPage, NotebookDirectory

    # Create a page at a nested path; intermediate directories are created as needed
    page = notebook.create(NotebookPage, "Experiments/2024/Results", parents=True)

    # Without parents=True, a RuntimeError is raised if an intermediate directory is missing
    page = notebook.create(NotebookPage, "Experiments/2024/Results")  # raises if missing

See :ref:`creating_pages` for details on the ``if_exists`` parameter and other creation options.

The NotebookPath Class
----------------------

:class:`~labapi.util.path.NotebookPath` is a structured path object that can be constructed from
nodes or strings, combined with ``/``, and converted back to strings. It is used internally by
``traverse`` and ``create``, but is also available for your own path logic.

**Constructing a path from a node:**

.. code-block:: python

    from labapi import NotebookPath

    path = NotebookPath(folder)
    print(path)           # /Experiments/2024
    print(path.name)      # 2024  (last segment)
    print(path.parts)     # ['Experiments']  (all but last)
    print(path.is_absolute())  # True

**Constructing from a string:**

.. code-block:: python

    abs_path = NotebookPath(None, "/Experiments/2024")
    rel_path = NotebookPath(None, "2024/Results")

**Combining paths with ``/``:**

.. code-block:: python

    base = NotebookPath(notebook)          # /
    path = base / "Experiments" / "2024"  # /Experiments/2024

**Resolving relative paths:**

.. code-block:: python

    rel = NotebookPath(None, "Results")
    abs_path = rel.resolve(NotebookPath(folder))  # /Experiments/2024/Results

**Getting a relative path between two nodes:**

.. code-block:: python

    page_path = NotebookPath(page)                  # /Experiments/2024/Results
    rel = page_path.relative_to(folder)             # Results  (relative to /Experiments/2024)

**Checking containment:**

.. code-block:: python

    page_path.is_relative_to(folder)   # True if page is inside folder
    page_path.is_relative_to(notebook) # True (everything is inside the notebook)
