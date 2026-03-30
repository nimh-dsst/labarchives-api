.. _integration_design:

Integration Design Guide
========================

This page is intentionally brief. Most integration behavior is already documented in
canonical guides, and this page focuses on the one genuinely new synthesis: a practical
cost model for system-level integrations.

Use these canonical references first:

* :ref:`index_access` — ID/name lookup semantics and duplicate-name behavior.
* :ref:`paths` — traversal and enumeration behavior.
* :doc:`api_calls` — low-level API access patterns.
* :ref:`clearing_cache` — object caching, ``refresh()``, and stale-reference caveats.

What this page adds: an integration cost model
----------------------------------------------

Cheap operations (usually in-memory)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Reading fields on objects you already loaded
* Reusing already materialized ``children`` / ``entries`` collections
* ID matching within those already materialized collections

Expensive operations (usually remote/API)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* First access to lazy collections (``children`` / ``entries``)
* ``refresh()`` followed by subsequent reads (invalidates cache, then refetches)
* Broad/deep tree traversal and repeated full enumeration
* Explicit low-level calls via ``user.api_get`` / ``user.api_post`` (and raw/stream calls)

Design implications for integrations
------------------------------------

* Prefer ID-first state in your integration model; names/paths are presentation and discovery.
* Keep traversal bounded (depth, scope, cadence) and favor incremental scans over full rescans.
* Place ``refresh()`` at sync boundaries where external mutation is plausible.
* After ``refresh()``, reacquire child objects from the refreshed parent before trusting child fields.
* When retrying after failures, re-resolve from a stable anchor (often a known parent + ID metadata)
  because there is no single global lookup-by-ID helper across notebooks.

Suggested reading order
-----------------------

1. :ref:`index_access`
2. :ref:`paths`
3. :ref:`clearing_cache`
4. :doc:`api_calls`
