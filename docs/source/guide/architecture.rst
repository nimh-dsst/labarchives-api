.. _architecture:

Contributor Architecture Guide
==============================

This guide documents the current internal architecture of ``labapi`` for
contributors working on tree, entry, and client internals.

The intent is to describe **current behavior and invariants**, including places
where the design is intentionally incomplete.

Subsystem map
-------------

At a high level, runtime flow goes through these layers:

1. :class:`~labapi.client.Client`
2. :class:`~labapi.user.User`
3. Tree model (:class:`~labapi.tree.collection.Notebooks` →
   :class:`~labapi.tree.notebook.Notebook` →
   :class:`~labapi.tree.directory.NotebookDirectory` /
   :class:`~labapi.tree.page.NotebookPage`)
4. Entry model (:class:`~labapi.entry.collection.Entries` and
   :class:`~labapi.entry.entries.base.Entry` subclasses)
5. Utility layer (:mod:`labapi.util` helpers such as
   :class:`~labapi.util.path.NotebookPath`,
   indexing types, and XML extraction)

Client and User boundary
~~~~~~~~~~~~~~~~~~~~~~~~

:class:`~labapi.client.Client` is responsible for connection/auth concerns and
request signing.
Its URL construction/signing helpers append the AKID, expiry, and HMAC-SHA512
signature to requests.

:class:`~labapi.user.User` wraps an authenticated session and provides
:meth:`~labapi.user.User.api_get`/:meth:`~labapi.user.User.api_post` that always
add ``uid``. Most internal modules call the API through
:class:`~labapi.user.User` rather than directly through
:class:`~labapi.client.Client`.

Tree model boundary
~~~~~~~~~~~~~~~~~~~

The tree model is split between mapping-style collections and node/container
mixins:

* :class:`~labapi.tree.collection.Notebooks` tracks the user-visible notebook
  list.
* :class:`~labapi.tree.notebook.Notebook` is both the logical root and a
  container.
* :class:`~labapi.tree.directory.NotebookDirectory` is a container node.
* :class:`~labapi.tree.page.NotebookPage` is a leaf node with lazy-loaded
  entries.

Most operations that mutate the notebook hierarchy are implemented in
``tree/mixins.py`` and then reused by concrete node types.

Entry model boundary
~~~~~~~~~~~~~~~~~~~~

:attr:`~labapi.tree.page.NotebookPage.entries` lazily fetches page entries and
materializes them as :class:`~labapi.entry.entries.base.Entry` subclasses.

The :class:`~labapi.entry.collection.Entries` collection owns page-level entry
creation methods and appends newly created entries to local state after
successful API calls.

Utility layer boundary
~~~~~~~~~~~~~~~~~~~~~~

The ``labapi.util`` package provides shared primitives that keep core modules
small and predictable:

* :class:`~labapi.util.path.NotebookPath` path normalization/resolution
* typed index markers (``Index.Id``/``Index.Name``)
* XML extraction and conversion helpers
* constants such as known part types

Cache model and invariants
--------------------------

Container population cache (``_populated``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:class:`~labapi.tree.mixins.AbstractTreeContainer` lazily loads children on
first access:

* :attr:`~labapi.tree.mixins.AbstractTreeContainer.children` and mapping access
  call :meth:`~labapi.tree.mixins.AbstractTreeContainer._ensure_populated`.
* :meth:`~labapi.tree.mixins.AbstractTreeContainer._ensure_populated` fetches
  ``tree_tools/get_tree_level`` once and marks the container as populated.
* :meth:`~labapi.tree.mixins.AbstractTreeContainer.refresh` clears
  ``_children`` and resets ``_populated=False``.

Invariant: while ``_populated`` is true, read APIs for that container should be
served from local ``_children`` without another tree-level API call.

Page entries cache (``_entries``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:attr:`~labapi.tree.page.NotebookPage.entries` is also lazy:

* ``_entries is None`` means "not loaded yet".
* first access fetches from ``tree_tools/get_entries_for_page`` and stores an
  :class:`~labapi.entry.collection.Entries` object.
* :meth:`~labapi.tree.page.NotebookPage.refresh` resets ``_entries`` back to
  ``None``.

Invariant: repeated ``page.entries`` access should return the same
:class:`~labapi.entry.collection.Entries` object until refresh.

Path cache (``_has_path``)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Every tree node memoizes its :class:`~labapi.util.NotebookPath`:

* first :attr:`~labapi.tree.mixins.AbstractBaseTreeNode.path` access computes
  and caches :class:`~labapi.util.path.NotebookPath` for the node.
* :meth:`~labapi.tree.mixins.AbstractTreeNode.move_to` explicitly invalidates
  only the moved node by setting ``_has_path=False``.

Invariant: cached paths are stable for nodes that have not moved.

Important caveat: descendants of moved containers are **not recursively path-
invalidated** today (see TODO section and issue ``#78``).

Path stability and traversal expectations
-----------------------------------------

:class:`~labapi.util.path.NotebookPath` canonicalizes path-like input and
supports:

* absolute and relative forms
* composition with ``/``
* resolution with parent anchors
* relative conversion via
  :meth:`~labapi.util.path.NotebookPath.relative_to`

Tree traversal uses path resolution semantics from
:class:`~labapi.util.path.NotebookPath`.
:meth:`~labapi.tree.mixins.AbstractBaseTreeNode.traverse` resolves relative
paths against ``self.path`` and then walks segments from ``self.root``.

Mutation invariants and refresh expectations
--------------------------------------------

General rule
~~~~~~~~~~~~

Mutating methods first call the API and then update local in-memory state when
the API call succeeds.

Create operations
~~~~~~~~~~~~~~~~~

:meth:`~labapi.tree.mixins.AbstractTreeContainer.create` inserts new nodes and
appends them to ``self._children``. For container nodes, the new node starts
with ``_populated=True`` and empty children.

When ``if_exists=InsertBehavior.Replace``, existing matching nodes are deleted
before creating a replacement.

Move operations
~~~~~~~~~~~~~~~

:meth:`~labapi.tree.mixins.AbstractTreeNode.move_to` updates the server parent,
then mutates both local parents:

* removes the node from old parent ``_children``
* switches ``_parent``
* appends to destination ``_children``
* invalidates only the moved node's cached path

Delete operations
~~~~~~~~~~~~~~~~~

:meth:`~labapi.tree.mixins.AbstractTreeNode.delete` is implemented as
move-to-trash semantics:

* ensure/create an ``API Deleted Items`` directory under notebook root
* rename node to include deletion timestamp
* call :meth:`~labapi.tree.mixins.AbstractTreeNode.move_to` with the trash
  folder as destination

This means local state continues to reference the same Python object, but under
its new parent and new name.

When to call refresh
~~~~~~~~~~~~~~~~~~~~

Use :meth:`~labapi.tree.mixins.AbstractTreeContainer.refresh` (or
:meth:`~labapi.tree.page.NotebookPage.refresh` for page entries) when external
changes may have occurred or when you need to force a re-fetch.

Current behavior is intentionally shallow:

* container ``refresh()`` clears child caches, but pre-existing child objects
  held elsewhere are not automatically reconciled
* page ``refresh()`` clears the page's entries cache, but existing entry
  instances are not invalidated in place

Entry registry and dispatch
---------------------------

:class:`~labapi.entry.entries.base.Entry` classes self-register through
:meth:`~labapi.entry.entries.base.Entry.__init_subclass__` by declaring a
``part_type``. The global registry maps ``part_type`` → class.

When page entries are loaded,
:meth:`~labapi.entry.entries.base.Entry.from_part_type` dispatches to the
registered class. Unknown/unsupported types are skipped with warnings in
:attr:`~labapi.tree.page.NotebookPage.entries`.

Known shortcuts and TODO areas
------------------------------

These are known design shortcuts that contributors should treat carefully:

* :meth:`~labapi.tree.mixins.AbstractTreeContainer.create` currently uses
  ``cls.__name__ == "NotebookPage"`` to choose ``is_folder`` value (issue
  ``#43``). This is brittle if class names change or new page-like types are
  added.
* Path invalidation after moves does not cascade to descendants (issue ``#78``).
  Moved containers can leave stale descendant ``path`` caches.
* Streaming/tree enumeration paths rely on ``StopIteration.value`` propagation
  behavior in generator internals (issue ``#54``), which is concise but less
  explicit than dedicated result objects.
* Additional TODO markers in core modules highlight incomplete areas:

  * container refresh does not reconcile detached child objects
  * page refresh does not invalidate existing entry objects
  * entry copy/upload and JSON helper workflows still contain implementation
    TODOs

Contributor checklist for internal changes
------------------------------------------

Before changing tree/entry/client internals:

1. Identify which cache invariants your change touches (``_populated``,
   ``_entries``, ``_has_path``).
2. Decide whether in-memory objects must be mutated immediately or whether
   :meth:`~labapi.tree.mixins.AbstractTreeContainer.refresh` /
   :meth:`~labapi.tree.page.NotebookPage.refresh` should be required.
3. Ensure parent/child bookkeeping stays symmetric for moves/deletes.
4. If you add or change entry types, confirm
   :meth:`~labapi.entry.entries.base.Entry.__init_subclass__` registry +
   :meth:`~labapi.entry.entries.base.Entry.from_part_type` dispatch behavior.
5. Update this page (and related guide pages) when module boundaries or
   invariants change.
