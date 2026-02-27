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
copyright = "2026, NIMH Data Science and Sharing Team"
author = "Christoph Li"

version = "0.1.0"
release = "0.1.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
]

autodoc_mock_imports = ["installed_browsers", "selenium"]

templates_path = ["_templates"]
exclude_patterns = []

language = "en"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]

# Intersphinx mapping
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "requests": ("https://requests.readthedocs.io/en/latest/", None),
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
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": False,
    "exclude-members": "__weakref__,__dict__,__module__",
    "private-members": False,
}

# Suppress cross-reference warnings for re-exported classes
suppress_warnings = ["ref.python"]



def process_docstring(app, what, name, obj, options, lines):
    """Remove :rtype: and :type: fields from docstrings since we show types in signatures."""
    # Remove lines in reverse to avoid index issues
    removed_count = 0
    i = len(lines) - 1
    while i >= 0:
        line = lines[i]
        stripped = line.strip()

        # Remove :rtype: field
        if stripped.startswith(":rtype:"):
            del lines[i]
            removed_count += 1
        # Remove :type param: fields
        elif stripped.startswith(":type "):
            del lines[i]
            removed_count += 1

        i -= 1

    # Debug: print when we remove something from Attachment
    if removed_count > 0 and "Attachment" in name:
        print(f"Removed {removed_count} type annotations from {name}")


def setup(app):
    app.connect("autodoc-skip-member", skip_member)
    # Run our docstring processor FIRST (priority 0) before any other processing
    app.connect("autodoc-process-docstring", process_docstring, priority=0)
