Navigating the Tree
===================

Once you have a :class:`~labapi.tree.notebook.Notebook` object, you can navigate its structure to find the pages and entries you need.
The notebook is organized as a tree, and you can move through it in several ways.

Traversing the tree with Paths
------------------------------

The most common way to navigate is using the :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.traverse` method. This method takes a 
path-like string and returns the object at that location.

.. code-block:: python

   # Get a page deep within the notebook
   page = notebook.traverse("Experiments/Project A/Results")

   # You can also traverse from any node, not just the notebook root
   experiments = notebook.traverse("Experiments")
   project_a = experiments.traverse("Project A")

Fluent Navigation (Ensure Methods)
----------------------------------

For a more "fluent" and concise navigation style, especially when you want to ensure a path exists while navigating,
you can use the :meth:`~labapi.tree.mixins.AbstractTreeContainer.dir` and
:meth:`~labapi.tree.mixins.AbstractTreeContainer.page` methods.

These methods act as "ensure" methods: they return the node if it exists, or create it if it's missing.

.. code-block:: python

   # Ensures the directory structure exists and returns the final page
   page = notebook.dir("Experiments").dir("Project A").page("Results")

   # Supports paths and automatic parent creation (parents=True by default)
   page = notebook.dir("Experiments/Project A").page("Results")

This style is particularly useful for setting up a notebook structure in a single chain of calls.
See :meth:`~labapi.tree.mixins.AbstractTreeContainer.create` for more granular control over
node creation (such as handling duplicates or replacing existing nodes).


Accessing Children by Name
--------------------------

You can access the immediate children of a node by their name using dictionary-style indexing. This will return the first child that
matches the given name.

.. code-block:: python

   # Get the "Experiments" directory
   experiments = notebook["Experiments"]

   # Get a page within the "Experiments" directory
   project_a = experiments["Project A"]

Accessing Children by ID or Name
--------------------------------

For more explicit lookups, you can use the :class:`~labapi.util.types.Index` object.

Accessing by ID
^^^^^^^^^^^^^^^^^^^^^^^^^^

To get a single child by its unique ID, use :attr:`~labapi.util.types.Index.Id`:

.. code-block:: python

   from labapi.util import Index

   # Get a specific page by its ID
   page = notebook[Index.Id:"123.45"]

Accessing by Name
^^^^^^^^^^^^^^^^^

To get a list of all children that match a given name, use :attr:`~labapi.util.types.Index.Name`:

.. code-block:: python

   from labapi.util import Index

   # Get all pages named "Results"
   results_pages = notebook[Index.Name:"Results"]

Finding Children
----------------

To discover what the contents of a directory are, ``labapi`` provides the following methods available on
:class:`~labapi.tree.notebook.Notebook` and :class:`~labapi.tree.directory.NotebookDirectory`:

Listing All Children
^^^^^^^^^^^^^^^^^^^^

:meth:`~labapi.tree.mixins.AbstractTreeContainer.enumerate_all` returns relative path strings for all descendants up to ``depth`` (default is 1):

.. code-block:: python

   all_items = notebook.enumerate_all()
   # Returns: ['Experiments', 'Notes']

   all_items = notebook.enumerate_all(depth=3)
   # Returns: ['Experiments', 'Experiments/2024', 'Experiments/2024/Results', 'Experiments/Archive', 'Notes']

   experiments = notebook['Experiments']
   experiment_items = experiments.enumerate_all(depth=2)
   # Returns: ['2024', '2024/Results', 'Archive']

.. note::
   The ``depth`` parameter controls how many levels deep to traverse in the tree structure:

   Given this tree structure::

      Notebook/
      ├── Experiments/
      │   ├── 2024/
      │   │   └── Results
      │   └── Archive
      └── Notes

   - ``depth=1`` returns: ``['Experiments', 'Notes']``
   - ``depth=2`` returns: ``['Experiments', 'Experiments/2024', 'Experiments/Archive', 'Notes']``
   - ``depth=3`` returns: ``['Experiments', 'Experiments/2024', 'Experiments/2024/Results', 'Experiments/Archive', 'Notes']``

Listing Only Directories
^^^^^^^^^^^^^^^^^^^^^^^^

:meth:`~labapi.tree.mixins.AbstractTreeContainer.enumerate_dirs` returns relative path strings for directories only:

.. code-block:: python

   directories = notebook.enumerate_dirs()
   # Returns: ['Experiments']

   directories = notebook.enumerate_dirs(depth=2)
   # Returns: ['Experiments', 'Experiments/2024']

   experiments = notebook['Experiments']
   subdirs = experiments.enumerate_dirs()
   # Returns: ['2024']

Listing Only Pages
^^^^^^^^^^^^^^^^^^

:meth:`~labapi.tree.mixins.AbstractTreeContainer.enumerate_pages` returns relative path strings for pages only:

.. code-block:: python

   pages = notebook.enumerate_pages()
   # Returns: ['Notes']

   pages = notebook.enumerate_pages(depth=2)
   # Returns: ['Experiments/Archive', 'Notes']

   experiments = notebook['Experiments']
   experiment_pages = experiments.enumerate_pages(depth=2)
   # Returns: ['Archive', '2024/Results']


Accessing the Parent
--------------------

Every node in the tree (except the root) has a :attr:`~labapi.tree.mixins.AbstractBaseTreeNode.parent` attribute that points to its parent node. 
The tree root is always a :class:`~labapi.tree.notebook.Notebook`, and its parent is itself.

.. code-block:: python

   page = notebook.traverse("Experiments/Project A/Results")
   project_a = page.parent  # This is the "Project A" directory

Accessing the Root
------------------

From any node in the tree, you can get to the root :class:`~labapi.tree.notebook.Notebook` object using 
the :attr:`~labapi.tree.mixins.AbstractBaseTreeNode.root` attribute.

.. code-block:: python

   page = notebook.traverse("Experiments/Project A/Results")
   notebook_root = page.root  # This is the notebook object

Checking for Directories
------------------------

You can check if a node is a directory (a container for other nodes) or a page (a leaf node) by using 
the :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.is_dir` method.

.. code-block:: python

   node = notebook.traverse("Experiments/Project A")
   if node.is_dir():
       print(f"{node.name} is a directory.")
   else:
       print(f"{node.name} is a page.")

Type-Safe Navigation
--------------------

When you are using a type checker, you can use the :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.as_dir` method to cast a node to a directory. 
This allows you to access directory-specific methods and attributes without your type checker complaining.

.. code-block:: python

    from labapi import NotebookPage

    node = notebook.traverse("Experiments/Project A")
    if node.is_dir():
        directory = node.as_dir()
        # Now you can access directory-specific methods
        directory.create(NotebookPage, "New Page")

If you call :meth:`~labapi.tree.mixins.AbstractBaseTreeNode.as_dir` on a node that is not a directory, it will raise a :class:`TypeError`.

