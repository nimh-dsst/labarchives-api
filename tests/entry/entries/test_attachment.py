"""Unit tests for AttachmentEntry class."""

from __future__ import annotations

from io import BytesIO
from unittest.mock import Mock

from labapi.entry.attachment import Attachment
from labapi.entry.entries.attachment import AttachmentEntry
from labapi.user import User


class TestAttachmentEntryUnit:
    """Pure unit tests with all dependencies mocked."""

    def test_attachment_entry_content_type(self):
        """Test AttachmentEntry.content_type returns 'Attachment'."""
        mock_user = Mock(spec=User)
        entry = AttachmentEntry("eid_att", "Test caption", mock_user)

        assert entry.content_type == "Attachment"

    def test_attachment_entry_caption(self):
        """Test AttachmentEntry.caption property returns the caption."""
        mock_user = Mock(spec=User)
        entry = AttachmentEntry("eid_att", "My attachment caption", mock_user)

        assert entry.caption == "My attachment caption"


class TestAttachmentEntryIntegration:
    """Integration tests with real objects and mocked API."""

    def test_attachment_entry_get_attachment(self, client, user: User):
        """Test AttachmentEntry.get_attachment fetches and caches attachment."""
        entry = AttachmentEntry("eid_att", "Test file", user)

        # Mock the stream_api_get method
        mock_response = Mock()
        mock_response.headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Disposition": 'attachment; filename="test.txt"',
        }

        def mock_stream():
            yield b"Test "
            yield b"file "
            yield b"content"
            return mock_response

        client.stream_api_get = Mock(return_value=mock_stream())

        # Get attachment
        attachment = entry.get_attachment(use_tempfile=False)

        # Verify attachment properties
        assert isinstance(attachment, Attachment)
        assert attachment.filename == "test.txt"
        assert attachment.mime_type == "text/plain"
        assert attachment.caption == "Test file"

        # Verify content
        assert attachment.read() == b"Test file content"

        # Verify API was called correctly
        client.stream_api_get.assert_called_once_with(
            "entries/entry_attachment", uid=user.id, eid="eid_att"
        )

    def test_attachment_entry_content_getter(self, client, user: User):
        """Test AttachmentEntry.content getter returns attachment."""
        entry = AttachmentEntry("eid_att", "Caption", user)

        # Mock stream_api_get
        mock_response = Mock()
        mock_response.headers = {
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="document.pdf"',
        }

        def mock_stream():
            yield b"PDF content"
            return mock_response

        client.stream_api_get = Mock(return_value=mock_stream())

        # Access content property
        attachment = entry.content

        assert isinstance(attachment, Attachment)
        assert attachment.filename == "document.pdf"
        assert attachment.mime_type == "application/pdf"

    def test_attachment_entry_content_setter(self, client, user: User):
        """Test AttachmentEntry.content setter uploads attachment."""
        entry = AttachmentEntry("eid_att", "Old caption", user)

        # Create a new attachment to upload
        backing = BytesIO(b"New file content")
        new_attachment = Attachment(
            backing=backing,
            mime_type="text/plain",
            filename="new_file.txt",
            caption="New caption",
        )

        # Mock API response
        client.api_response = """<?xml version="1.0" encoding="UTF-8"?>
        <entry>
            <success>true</success>
        </entry>
        """

        # Update content
        entry.content = new_attachment

        # Verify API call
        api_call = client.api_log
        assert api_call[0] == "entries/update_attachment"
        assert api_call[1]["filename"] == "new_file.txt"
        assert api_call[1]["caption"] == "New caption"
        assert api_call[1]["eid"] == "eid_att"

    def test_attachment_entry_get_attachment_caching(self, client, user: User):
        """Test AttachmentEntry.get_attachment caches the result."""
        entry = AttachmentEntry("eid_att", "Caption", user)

        # Mock stream_api_get
        mock_response = Mock()
        mock_response.headers = {
            "Content-Type": "text/plain",
            "Content-Disposition": 'attachment; filename="test.txt"',
        }

        def mock_stream():
            yield b"Content"
            return mock_response

        client.stream_api_get = Mock(return_value=mock_stream())

        # First call
        attachment1 = entry.get_attachment()
        assert client.stream_api_get.call_count == 1

        # Second call should use cached data
        attachment2 = entry.get_attachment()
        assert client.stream_api_get.call_count == 1  # Not called again

        # Should be same object
        assert attachment1 is attachment2
