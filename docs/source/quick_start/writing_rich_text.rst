.. _writing_rich_text:

Writing Rich Text Entries
=========================

LabArchives's rich text entries use HTML for formatting. This allows you to create entries with various styles, 
including text formatting, tables, and lists. For a complete tag reference, see the `MDN HTML elements reference <https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements>`_.

Creating a Rich Text Entry
--------------------------

To create a rich text entry, you can use the :meth:`~labapi.entry.collection.Entries.create` method on 
a :class:`~labapi.tree.page.NotebookPage` object.

.. code-block:: python

    from labapi import TextEntry
    my_page.entries.create(TextEntry, "<p>This is a rich text entry.</p>")

Paragraphs
----------

The ``<p>`` tag is used to define a paragraph. Browsers automatically add some space (a margin) before and after each ``<p>`` element.

.. code-block:: html

    <p>This is a paragraph.</p>
    <p>This is another paragraph.</p>

Text Formatting
---------------

You can use standard HTML tags for text formatting.

- **Bold:** ``<b>bold text</b>``
- *Italic:* ``<i>italic text</i>``
- <u>Underline:</u> ``<u>underlined text</u>``
- <s>Strikethrough:</s> ``<s>strikethrough text</s>``

Example:
""""""""

.. code-block:: html

    <p>
        This paragraph contains <b>bold</b>, 
        <i>italic</i>, 
        <u>underlined</u>, 
        and <s>strikethrough</s> text.
    </p>

Changing Text Color
-------------------

You can change the color of your text using the ``style`` attribute with the ``color`` property.

.. code-block:: html

    <p style="color:red;">This text is red.</p>
    <p style="color:blue;">This text is blue.</p>

You can also use hexadecimal color codes:

.. code-block:: html

    <p style="color:#ff0000;">This text is red.</p>
    <p style="color:#0000ff;">This text is blue.</p>

Tables
------

You can create tables using the ``<table>``, ``<tr>``, ``<th>``, and ``<td>`` HTML tags.

Example:
""""""""

.. code-block:: html

    <table border="1">
        <tr>
            <th>Header 1</th>
            <th>Header 2</th>
        </tr>
        <tr>
            <td>Row 1, Cell 1</td>
            <td>Row 1, Cell 2</td>
        </tr>
        <tr>
            <td>Row 2, Cell 1</td>
            <td>Row 2, Cell 2</td>
        </tr>
    </table>

Lists
-----

You can create ordered and unordered lists using the ``<ol>``, ``<ul>``, and ``<li>`` HTML tags.

Unordered List Example:
"""""""""""""""""""""""

.. code-block:: html

    <ul>
        <li>Item 1</li>
        <li>Item 2</li>
        <li>Item 3</li>
    </ul>

Ordered List Example:
"""""""""""""""""""""

.. code-block:: html

    <ol>
        <li>First item</li>
        <li>Second item</li>
        <li>Third item</li>
    </ol>

See also
--------

- :ref:`entries` for entry type behavior and update semantics.
- :doc:`/examples/csv_table` for converting tabular data to HTML table markup.
- :ref:`faq` for certificate and browser settings that can affect scripted workflows.
