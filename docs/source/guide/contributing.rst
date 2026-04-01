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

    uv sync --all-groups
    pre-commit install --hook-type pre-commit --hook-type pre-push

Running Tests
-------------

The test suite is split into unit tests and integration tests. Plain ``pytest`` deselects integration tests by
default

To run the full suite, including integration tests:

.. code-block:: bash

    uv run pytest --integration

Unit tests
~~~~~~~~~~

Unit tests use a ``MockClient`` that replays pre-recorded API responses, so
they run entirely offline. 

.. code-block:: bash

    uv run pytest

Coverage is reported automatically. To skip the report and just see pass/fail:

.. code-block:: bash

    uv run pytest --no-cov

To run a single test file:

.. code-block:: bash

    uv run pytest tests/tree/test_mixins.py

Integration tests
~~~~~~~~~~~~~~~~~

Integration tests hit the live LabArchives API and require credentials in the
environment (or a ``.env`` file):

.. code-block:: bash

    # Required
    ACCESS_KEYID=your_akid
    ACCESS_PWD=your_password
    API_URL=https://api.labarchives.com

    # Required for non-interactive login used by tests/test_integration.py
    AUTH_EMAIL=your@email.com
    AUTH_KEY=your_auth_key

    # Optional: use the browser callback flow instead
    # AUTH_INTERACTIVE=true

Run them explicitly:

.. code-block:: bash

    uv run pytest --integration tests/test_integration.py

.. note::

   ``Client()`` only auto-loads ``API_URL``, ``ACCESS_KEYID``, and
   ``ACCESS_PWD``. ``AUTH_EMAIL`` and ``AUTH_KEY`` are conventions used by
   this repository's integration-test fixtures.

Code Style
----------

``labapi`` uses `Ruff <https://docs.astral.sh/ruff/>`_ for both linting and
formatting.

Pre-commit hooks
~~~~~~~~~~~~~~~~

After running ``pre-commit install --hook-type pre-commit --hook-type pre-push``:

* **ruff-check** - lints and auto-fixes safe issues (``--fix``)
* **ruff-format** - enforces consistent formatting
* **pytest-check** - runs ``uv run pytest --no-cov`` on ``pre-push``

You can run them manually at any time:

.. code-block:: bash

    uv run ruff check --fix .
    uv run ruff format .
    uv run pytest --no-cov

Or check without making changes:

.. code-block:: bash

    uv run ruff check .
    uv run ruff format --check .

Type checking
~~~~~~~~~~~~~

``labapi`` uses `Pyright <https://github.com/microsoft/pyright>`_ for static
type checking.

Run it locally with:

.. code-block:: bash

    uv run pyright

Continuous integration
~~~~~~~~~~~~~~~~~~~~~~

GitHub Actions split the main quality gates into separate workflows under
``.github/workflows``:

* unit tests
* lint
* format
* typecheck
* docs
* manual integration tests

Keeping these commands green locally is the fastest way to avoid CI surprises.

Type System
-----------

``labapi`` uses Python's type system as a first-class tool rather than
optional documentation. All new code must be fully type-annotated.

Key conventions:

* **``from __future__ import annotations``** is present in every module,
  enabling postponed evaluation of annotations and allowing forward references
  without string literals.
* **Generics** are used throughout the entry system - :class:`~labapi.entry.entries.base.Entry`
  is parameterized by its data type (e.g., ``Entry[Attachment]``), so callers
  get concrete return types without casting.
* **``TYPE_CHECKING`` guards** prevent circular imports while keeping type
  information available to static checkers.
* **``override``** is applied to all method overrides, so a missing base
  method is caught at check time rather than silently becoming dead code.
* **``overload``** is used on ``__getitem__`` to express the different return
  types produced by different index kinds.

The project targets Python 3.12+ and uses modern syntax where it improves
clarity - ``type`` aliases, ``match`` statements, and ``Self``.
