import unittest
from email.message import EmailMessage
from phishguard.features.extractors import extract_urls, extract_attachments


class TestFeatures(unittest.TestCase):
    def test_extract_urls_plain_and_html_pairs(self):
        """
        Test that extract_urls correctly finds URLs in both plain text and HTML email bodies.
        - The plain text body contains a single URL: "http://a.example/path".
        - The HTML body contains an anchor tag with href="/login" and anchor text "text".
        - The HTML also includes a <base> tag, so the relative URL should resolve to "https://b.example/login".
        - The test checks:
            * The plain text URL is present in the extracted URLs list.
            * The anchor text and resolved URL pair ("text", "https://b.example/login") is present in the extracted pairs.
        """
        body_text = "Visit http://a.example/path"
        body_html = """<html><head><base href="https://b.example/root/"></head>
        <body><a href="/login">text</a></body></html>"""
        urls, pairs = extract_urls(body_text, body_html)
        self.assertIn("http://a.example/path", urls)
        self.assertIn(("text", "https://b.example/login"), pairs)

    def test_base_tag_resolution(self):
        """
        Test that extract_urls correctly resolves relative URLs using the <base> tag in HTML.
        - The HTML body contains a <base> tag with href="https://base.example/".
        - There are two anchor tags with relative hrefs: "/path1" and "path2".
        - The test checks:
            * The resolved URLs "https://base.example/path1" and "https://base.example/path2" are present in the extracted URLs list.
        """
        body_html = """<html><head><base href="https://base.example/"></head>
        <body>
            <a href="/path1">Link 1</a>
            <a href="/path2">Link 2</a>
        </body></html>"""
        urls, pairs = extract_urls("", body_html)
        self.assertIn("https://base.example/path1", urls)
        self.assertIn("https://base.example/path2", urls)

    def test_list_attachments_names(self):
        """
        Test that list_attachments returns the correct, normalized filenames of attachments in an email.
        - An EmailMessage is created with a single PDF attachment named "Invoice.PDF".
        - The function should return a list of attachment filenames, all lowercased.
        - The test checks:
            * The returned list contains "invoice.pdf", confirming normalization and extraction.
        """
        msg = EmailMessage()
        msg["Subject"] = "Files"
        msg.set_content("see attachment")
        # add attachment
        msg.add_attachment(b"PDF BYTES", maintype="application", subtype="pdf", filename="Invoice.PDF")
        names = extract_attachments(msg)
        self.assertIn("invoice.pdf", names)


if __name__ == "__main__":
    unittest.main()
