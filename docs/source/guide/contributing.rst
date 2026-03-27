.. _contributing:

Contributing
============

This page covers the development workflow for ``labapi``: running tests,
enforcing code style, and following the project's conventions around the type
system.

Setup
-----

Install the package with its development dependencies using ``uv``:

.. code-block:: bash

    uv sync
    source .venv/bin/activate
    pre-commit install

Running Tests
-------------

The test suite is split into unit tests and integration tests.

Unit tests
~~~~~~~~~~

Unit tests use a ``MockClient`` that replays pre-recorded API responses, so
they run entirely offline. Plain ``pytest`` deselects integration tests by
default:

.. code-block:: bash

    pytest

Coverage is reported automatically. To skip the report and just see pass/fail:

.. code-block:: bash

    pytest --no-cov

To run a single test file:

.. code-block:: bash

    pytest tests/tree/test_mixins.py

Integration tests
~~~~~~~~~~~~~~~~~

Integration tests hit the live LabArchives API and require credentials in the
environment (or a ``.env`` file):

.. code-block:: bash

    # Required
    ACCESS_KEYID=your_akid
    ACCESS_PWD=your_password
    API_URL=https://api.labarchives.com

    # Required for non-interactive login
    AUTH_EMAIL=your@email.com
    AUTH_KEY=your_auth_key

Run them explicitly:

.. code-block:: bash

    pytest --integration tests/test_integration.py

To run the full suite, including integration tests:

.. code-block:: bash

    pytest --integration

Code Style
----------

``labapi`` uses `Ruff <https://docs.astral.sh/ruff/>`_ for both linting and
formatting.

Pre-commit hooks
~~~~~~~~~~~~~~~~

After running ``pre-commit install``, Ruff runs automatically on every commit:

* **ruff-check** — lints and auto-fixes safe issues (``--fix``)
* **ruff-format** — enforces consistent formatting

You can run them manually at any time:

.. code-block:: bash

    ruff check --fix .
    ruff format .

Or check without making changes:

.. code-block:: bash

    ruff check .
    ruff format --check .

Type System
-----------

``labapi`` uses Python's type system as a first-class tool rather than
optional documentation. All new code must be fully type-annotated.

Key conventions:

* **``from __future__ import annotations``** is present in every module,
  enabling postponed evaluation of annotations and allowing forward references
  without string literals.
* **Generics** are used throughout the entry system — :class:`~labapi.entry.entries.base.Entry`
  is parameterized by its data type (e.g., ``Entry[Attachment]``), so callers
  get concrete return types without casting.
* **``TYPE_CHECKING`` guards** prevent circular imports while keeping type
  information available to static checkers.
* **``override``** is applied to all method overrides, so a missing base
  method is caught at check time rather than silently becoming dead code.
* **``overload``** is used on ``__getitem__`` to express the different return
  types produced by different index kinds.

The project targets Python 3.12+ and uses modern syntax where it improves
clarity — ``type`` aliases, ``match`` statements, and ``Self``.
