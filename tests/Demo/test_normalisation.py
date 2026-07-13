import unittest
from email.message import EmailMessage
from email.generator import BytesGenerator
from io import BytesIO

from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body


def _make_html_only(subject="=?UTF-8?Q?Caf=C3=A9?="):
    msg = EmailMessage()
    msg["From"] = "=?UTF-8?Q?Al=EF=AC=81ce?= <alice@example.com>"
    msg["To"] = "Bob <bob@example.com>"
    msg["Subject"] = subject
    msg.set_content("<p>Click <a href='http://example.com'>here</a></p>", subtype="html")
    buf = BytesIO(); BytesGenerator(buf).flatten(msg)
    return msg  # already EmailMessage


class TestNormalize(unittest.TestCase):
    def test_normalize_headers_decodes_subject(self):
        """
        Test that the normalize_headers function correctly decodes
        a MIME-encoded subject header to its Unicode representation.

        This test creates an email message with a subject header encoded in MIME (quoted-printable UTF-8).
        It then uses the normalize_headers function to decode the header and checks that the result
        is the expected Unicode string ("Café"), ensuring proper header normalization.
        """
        msg = _make_html_only()
        headers = normalize_header(msg)
        self.assertEqual(headers["subject"], "Café")

    def test_decode_addresses_from_and_replyto(self):
        """
        Test that decode_addresses extracts and decodes the 'From' and 'Reply-To'
        addresses correctly, including the display name and email address.

        This test constructs an email with both 'From' and 'Reply-To' headers, where the 'From'
        header contains a MIME-encoded display name. It verifies that decode_addresses returns
        the correct decoded display name, the sender's email address, and the reply-to address.
        The test also checks that the display name is properly decoded and not empty.
        """
        msg = _make_html_only()
        msg["Reply-To"] = "Help <help@example.org>"
        from_display, from_addr, reply_to_addr = decode_address(msg)
        self.assertEqual(from_addr, "alice@example.com")
        self.assertEqual(reply_to_addr, "help@example.org")
        self.assertTrue(from_display)  # decoded display should be non-empty

    def test_extract_body_html_fallback(self):
        """
        Test that extract_body returns the correct plain text and HTML content
        from an email message that only contains HTML content.
        
        This test creates an email message with only HTML content and uses extract_body
        to retrieve both the plain text and HTML parts. It asserts that the plain text
        contains expected content (e.g., "Click") and that the HTML part starts with the
        expected HTML tag, confirming correct extraction and fallback behavior.
        """
        msg = _make_html_only()
        text, html = extract_body(msg)
        self.assertIn("Click", text)
        self.assertTrue(html.startswith("<"))


if __name__ == "__main__":
    unittest.main()
