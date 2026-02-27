# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys

sys.path.insert(0, os.path.abspath("../../src"))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "labapi"
copyright = "2026, Your Name"
author = "Christoph Li <christoph.li@nih.gov>"

version = "0.1.0"
release = "0.1.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.extlinks",
    "sphinx.ext.intersphinx",
    "sphinx.ext.autosummary",
    "sphinx_copybutton",
    "sphinx_design"
]

autodoc_mock_imports = ["installed_browsers", "selenium"]
autosummary_mock_imports = ["installed_browsers", "selenium"]

templates_path = ["_templates"]
exclude_patterns = []

language = "en"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "breeze"
html_static_path = ["_static"]

# Intersphinx mapping
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "requests": ("https://requests.readthedocs.io/en/latest/", None),
    "lxml": ("https://lxml.de/apidoc/", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
    "selenium": ("https://www.selenium.dev/selenium/docs/api/py/", None),
}

# Napoleon settings for Google and NumPy style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_use_rtype = False  # Don't show redundant "Return type:" field
napoleon_use_param = True  # Keep parameter descriptions
napoleon_preprocess_types = True  # Simplify type names

# Autodoc settings
autodoc_typehints = "signature"  # Show type hints in function signatures
autodoc_typehints_format = "short"  # Use short type names (List instead of typing.List)
autodoc_member_order = "bysource"

# Suppress cross-reference warnings for re-exported classes
suppress_warnings = ["ref.python"]

sphinx_tabs_disable_tab_closing = True
