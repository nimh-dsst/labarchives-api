.. _index_access:

Accessing Items with Index
==========================

The ``Index`` utility, located in ``labapi.util``, is used to specify how you want to index into a collection.

Supported Collection Types
--------------------------

This indexing method is supported by the following collection types:

1. **``Notebooks``**: The collection of notebooks associated with a user (e.g., ``user.notebooks``).
2. **Tree Containers**: Any object that acts as a container for other tree nodes, including **``Notebook``** and **``NotebookDirectory``** (e.g., ``notebook["Folder"]``).

.. warning::
   This indexing method is **not** supported for page **``Entries``**. Page entries must be accessed by their integer index or via iteration.

.. note::
   Iterating over ``user.notebooks`` or a tree container yields names. Use ``values()`` to iterate over notebook or node objects, or ``items()`` to iterate over ``(name, object)`` pairs.

Basic Access by Name
--------------------

By default, using a string as a key will look up an item by its name.

.. code-block:: python

    # Access a notebook by name
    notebook = user.notebooks["My Research Notebook"]

    # Access a child directory or page by name
    experiments = notebook["Experiments"]

.. note::
   If multiple items have the same name, the first match is returned.
   The ``keys()``, ``items()``, and ``values()`` helpers on ``Notebooks`` and
   tree containers follow standard mapping semantics.
   Use ``all_keys()``, ``all_items()``, and ``all_values()``
   when you need ordered, duplicate-preserving results.

Explicit Indexing with Index
----------------------------

For more control, or to access items by ID, use the ``Index`` enumeration.

Access by ID
~~~~~~~~~~~~

Since IDs are unique within LabArchives, this is the most reliable way to access a specific item.

.. code-block:: python

    from labapi import Index

    # Access a notebook by its unique ID
    notebook = user.notebooks[Index.Id: "12345"]

    # Access a child node by its tree ID
    page = notebook[Index.Id: "67890"]

Access by Name (Explicit)
~~~~~~~~~~~~~~~~~~~~~~~~~

You can also explicitly state that you are looking up an item by name. This is particularly useful when you want to retrieve *all* items with a certain name, as names in LabArchives are not guaranteed to be unique.

.. code-block:: python

    from labapi import Index

    # Get a list of all notebooks named "Shared Data"
    shared_notebooks = user.notebooks[Index.Name: "Shared Data"]

    # Get all children named "Protocol" within a directory
    protocols = experiments[Index.Name: "Protocol"]

Summary of Indexing Methods
---------------------------

+---------------------------+-----------------------------------+------------------------------------------+
| Syntax                    | Method                            | Returns                                  |
+===========================+===================================+==========================================+
| ``coll["name"]``          | Implicit Name Lookup              | First item with matching name            |
+---------------------------+-----------------------------------+------------------------------------------+
| ``coll[Index.Id: "id"]``  | Explicit ID Lookup                | The unique item with matching ID         |
+---------------------------+-----------------------------------+------------------------------------------+
| ``coll[Index.Name: "n"]`` | Explicit Name List                | A list of all items with matching name   |
+---------------------------+-----------------------------------+------------------------------------------+

Related Pages
-------------

* :ref:`limitations`
