"""Unit tests for Attachment class."""

from __future__ import annotations

import tempfile
from io import BytesIO
from pathlib import Path


from labapi.entry.attachment import Attachment


def test_attachment_from_file():
    """Test creating Attachment from a file object."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(
        mode="w+b", suffix=".txt", delete=False
    ) as temp_file:
        temp_file.write(b"Test content")
        temp_file_path = temp_file.name

    try:
        # Open the file and create attachment
        with open(temp_file_path, "r+b") as file:
            attachment = Attachment.from_file(file)

            assert attachment.filename == temp_file_path
            assert attachment.mime_type == "text/plain"
            assert attachment.caption == "API-uploaded text/plain file."
    finally:
        # Clean up
        Path(temp_file_path).unlink(missing_ok=True)


def test_attachment_from_file_buffered_reader():
    """Test creating Attachment from a BufferedReader (opened with rb)."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(
        mode="w+b", suffix=".txt", delete=False
    ) as temp_file:
        temp_file.write(b"Test content for BufferedReader")
        temp_file_path = temp_file.name

    try:
        # Open the file with 'rb' (read-only binary mode)
        with open(temp_file_path, "rb") as file:
            attachment = Attachment.from_file(file)

            # Read content from attachment to verify cloning
            assert attachment.read() == b"Test content for BufferedReader"
            assert attachment.filename == temp_file_path
            assert attachment.mime_type == "text/plain"
    finally:
        # Clean up
        Path(temp_file_path).unlink(missing_ok=True)


def test_attachment_from_file_unknown_mimetype():
    """Test creating Attachment from a file with unknown MIME type."""
    # Create a file with unknown extension
    with tempfile.NamedTemporaryFile(
        mode="w+b", suffix=".unknownext", delete=False
    ) as temp_file:
        temp_file.write(b"Test content")
        temp_file_path = temp_file.name

    try:
        with open(temp_file_path, "r+b") as file:
            attachment = Attachment.from_file(file)

            assert attachment.mime_type == "application/octet-stream"
            assert attachment.caption == "API-uploaded application/octet-stream file."
    finally:
        Path(temp_file_path).unlink(missing_ok=True)


def test_attachment_initialization():
    """Test Attachment initialization with all parameters."""
    backing = BytesIO(b"Test data")
    attachment = Attachment(
        backing=backing,
        mime_type="image/png",
        filename="test.png",
        caption="Test image",
    )

    assert attachment.mime_type == "image/png"
    assert attachment.filename == "test.png"
    assert attachment.caption == "Test image"


def test_attachment_properties():
    """Test Attachment property access."""
    backing = BytesIO(b"Sample content")
    attachment = Attachment(
        backing=backing,
        mime_type="application/pdf",
        filename="document.pdf",
        caption="A test document",
    )

    # Test property getters
    assert attachment.filename == "document.pdf"
    assert attachment.mime_type == "application/pdf"
    assert attachment.caption == "A test document"


def test_attachment_getattr_delegation():
    """Test that Attachment delegates attribute access to backing object."""
    backing = BytesIO(b"Hello World")
    attachment = Attachment(
        backing=backing,
        mime_type="text/plain",
        filename="hello.txt",
        caption="Greeting",
    )

    # Test delegated read operation
    content = attachment.read()
    assert content == b"Hello World"

    # Test delegated seek operation
    attachment.seek(0)
    content = attachment.read(5)
    assert content == b"Hello"


def test_attachment_seeks_to_beginning():
    """Test that Attachment seeks to beginning of seekable backing."""
    backing = BytesIO(b"Test")
    backing.seek(2)  # Move to middle

    Attachment(
        backing=backing,
        mime_type="text/plain",
        filename="test.txt",
        caption="Test",
    )

    # Should be at position 0 after initialization
    assert backing.tell() == 0
