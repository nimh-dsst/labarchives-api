.. _exceptions:

Exception Types
===============

``labapi`` exposes a small set of public exception classes at the top level so
callers can reliably catch failures by category.

Public Exception Hierarchy
--------------------------

All custom exceptions inherit from :class:`~labapi.LabArchivesError`:

.. code-block:: text

   Exception
   `-- LabArchivesError
       |-- AuthenticationError
       |-- ApiError
       |-- NodeExistsError
       `-- TraversalError

Import and catch these from ``labapi``:

.. code-block:: python

   from labapi import LabArchivesError, NodeExistsError, NotebookPage, TraversalError

   try:
       page = notebook.create(NotebookPage, "Experiments/2024/Results")
   except NodeExistsError:
       ...
   except ValueError:
       ...
   except TraversalError:
       ...
   except LabArchivesError:
       ...

Common Operations and Raised Exceptions
---------------------------------------

:meth:`~labapi.tree.mixins.AbstractTreeContainer.create`
   Raises :class:`~labapi.NodeExistsError` when creating a duplicate node with
   ``if_exists=InsertBehavior.Raise``.

   Raises :class:`ValueError` when creating a multi-segment path without
   ``parents=True`` and an intermediate parent is missing.

:meth:`~labapi.tree.mixins.AbstractBaseTreeNode.traverse`
   Raises :class:`~labapi.TraversalError` when an intermediate path segment
   exists but is not a directory.

Related Pages
-------------

- :ref:`paths` for traversal rules and parent-navigation behavior.
- :ref:`creating_pages` for duplicate-create behavior in practice.
- :ref:`limitations` for broader operational caveats.
