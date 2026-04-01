.. _integration_design:

Integration Design Guide
========================

This page ties together the behavior described elsewhere in the guide and turns
it into practical rules of thumb for long-running integrations.

Integration Cost Model
----------------------

Cheap Operations
~~~~~~~~~~~~~~~~

These are usually in-memory:

- Reading fields on objects you already loaded.
- Reusing materialized ``children`` and ``entries`` collections.
- Matching IDs inside collections you already fetched.

Expensive Operations
~~~~~~~~~~~~~~~~~~~~

These usually trigger remote work:

- First access to lazy collections such as ``children`` and ``entries``.
- Calling ``refresh()`` and then reading the same objects again.
- Broad tree traversal or repeated full enumeration.
- Explicit low-level calls through ``user.api_get`` and ``user.api_post``.

Design Guidelines
-----------------

- Prefer ID-first state in your integration model. Names and paths are best
  treated as discovery and presentation data.
- Keep traversal bounded by scope and depth, and favor incremental scans over
  full rescans.
- Place ``refresh()`` at synchronization boundaries where outside mutation is
  plausible.
- After ``refresh()``, reacquire child objects from the refreshed parent before
  trusting child fields.
- After failures, re-resolve from a stable anchor such as a known parent plus
  stored ID metadata.

Suggested Reading Order
-----------------------

1. :ref:`index_access`
2. :ref:`paths`
3. :ref:`clearing_cache`
4. :ref:`api_calls`

Related Pages
-------------

- :ref:`index_access` for duplicate-name and explicit lookup behavior.
- :ref:`paths` for traversal and enumeration rules.
- :ref:`clearing_cache` for cache invalidation and stale-reference behavior.
- :ref:`api_calls` for low-level request access patterns.
