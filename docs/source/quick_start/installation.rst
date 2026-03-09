Installation
============

Python Version
--------------

Supports Python 3.12 and newer.


Dependencies
------------
* `cryptography <https://cryptography.io/en/latest/>`_ is a package providing cryptographic primitives, 
  in this library used to sign API requests.
* `lxml <https://lxml.de/apidoc/>`_ is a Pythonic XML library binding. It is used to parse API responses.
* `requests <https://requests.readthedocs.io/en/latest/>`_ is a simple HTTP library used to interact 
  with the LabArchives API.

Install
-------

We recommend using uv to install labapi.

.. tab-set::

  .. tab-item:: uv

    .. code-block:: bash

      uv add labapi

  .. tab-item:: poetry

    .. code-block:: bash

      poetry add labapi
  
  .. tab-item:: pip
    
    .. code-block:: bash
      
      pip install labapi


.. _optional-deps:

Optional Dependencies
---------------------

``labapi`` comes with two optional dependency groups:

.. dropdown:: builtin-auth

  This group of dependencies allows the :meth:`~labapi.client.Client.default_authenticate` function to open 
  browser windows for higher quality-of-life when running locally.

  .. tab-set::

    .. tab-item:: uv

      .. code-block:: bash

        uv add labapi --optional builtin-auth

    .. tab-item:: poetry

      .. code-block:: bash

        poetry install labapi --with builtin-auth
    
    .. tab-item:: pip
      
      .. code-block:: bash
        
        pip install 'labapi[builtin-auth]'

.. dropdown:: dotenv

  This group of dependencies allows the :class:`~labapi.client.Client` constructor to use environment variables 
  specified in the ``.env`` file in a project.

  .. tab-set::

    .. tab-item:: uv

      .. code-block:: bash

        uv add labapi --optional dotenv

    .. tab-item:: poetry

      .. code-block:: bash

        poetry install labapi --with dotenv
    
    .. tab-item:: pip
      
      .. code-block:: bash
        
        pip install 'labapi[dotenv]'









