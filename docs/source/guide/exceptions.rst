.. _exceptions:

Exception Types
===============

``labapi`` exposes a small set of public exception classes at the top level so callers can
reliably catch failures by category.

Public exception hierarchy
--------------------------

All custom exceptions inherit from :class:`~labapi.LabArchivesError`:

.. code-block:: text

    Exception
    └── LabArchivesError
        ├── AuthenticationError
        ├── ApiError
        ├── NodeExistsError
        └── TraversalError

Import and catch these from ``labapi``:

.. code-block:: python

    from labapi import LabArchivesError, NodeExistsError, NotebookPage, TraversalError

    try:
        page = notebook.create(NotebookPage, "Experiments/2024/Results")
    except NodeExistsError:
        # Duplicate create with InsertBehavior.Raise
        ...
    except ValueError:
        # Missing intermediate path segments when parents=False
        ...
    except TraversalError:
        # Traversal hit a non-directory segment
        ...
    except LabArchivesError:
        # Other library-specific errors (API/auth/etc.)
        ...

Common operations and raised exceptions
---------------------------------------

- :meth:`~labapi.tree.mixins.AbstractTreeContainer.create`

  - Raises :class:`~labapi.NodeExistsError` when creating a duplicate node with
    ``if_exists=InsertBehavior.Raise``.
  - Raises :class:`ValueError` when creating a multi-segment path without ``parents=True``
    and an intermediate parent is missing.

- :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.traverse`

  - Raises :class:`~labapi.TraversalError` when an intermediate path segment exists but is
    not a directory.
