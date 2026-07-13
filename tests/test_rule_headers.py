import unittest
from types import SimpleNamespace
from phishguard.rules.headers import rule_headers_analyse
from phishguard.schema import RuleHit, Severity, EmailRecord  
from phishguard.config import load_config

# Load configuration for URL red flag detection
CFG = load_config()



"""
Test 1: Headers all correct → passes

Test 2: FROM header mismatch → flagged

Test 3: REPLY-TO mismatch → flagged

Test 4: TO header contains “Undisclosed recipients” → flagged

Test 5: RECEIVED header exceeds max hops → flagged

"""

class TestRuleHeadersAnalyse(unittest.TestCase):
    def test_matching_headers(self):
        """Test email where all headers match and no anomalies."""
        rec = EmailRecord(
            from_display="Alice",
            from_addr="alice@example.com",
            reply_to_addr="alice@example.com",
            subject="Hello",
            body_text="Test email",
            body_html=None,
            urls=[],
            url_display_pairs=[],
            attachments=[],
            headers={
                "from": "Alice <alice@example.com>",
                "reply-to": "alice@example.com",
                "to": "bob@example.com",
                "received": "server1\nserver2"
            },
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True
        )
        result: RuleHit = rule_headers_analyse(rec, CFG)
        self.assertTrue(result.passed)
        self.assertEqual(result.score_delta, 0.0)
        self.assertEqual(result.severity, Severity.LOW)

    def test_from_header_mismatch(self):
        """Test mismatch between display name and local part."""
        rec = EmailRecord(
            from_display="Bob",
            from_addr="alice@example.com",
            reply_to_addr="alice@example.com",
            subject="Hello",
            body_text="Test email",
            body_html=None,
            urls=[],
            url_display_pairs=[],
            attachments=[],
            headers={
                "from": "Bob <alice@example.com>",
                "reply-to": "alice@example.com",
                "to": "bob@example.com",
                "received": "server1\nserver2"
            },
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True
        )
        result: RuleHit = rule_headers_analyse(rec, CFG)
        self.assertFalse(result.passed)
        self.assertIn("from_header", result.details)
        self.assertEqual(result.score_delta, 0.5)

    def test_reply_to_mismatch(self):
        """Test when Reply-To domain differs from From domain."""
        rec = EmailRecord(
            from_display="Alice",
            from_addr="alice@example.com",
            reply_to_addr="bob@other.com",
            subject="Hello",
            body_text="Test email",
            body_html=None,
            urls=[],
            url_display_pairs=[],
            attachments=[],
            headers={
                "from": "Alice <alice@example.com>",
                "reply-to": "bob@other.com",
                "to": "bob@example.com",
                "received": "server1\nserver2"
            },
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True
        )
        result: RuleHit = rule_headers_analyse(rec, CFG)
        self.assertFalse(result.passed)
        self.assertIn("reply_to", result.details)
        self.assertEqual(result.score_delta, 0.5)

    def test_undisclosed_recipients(self):
        """Test detection of undisclosed recipients."""
        rec = EmailRecord(
            from_display="Alice",
            from_addr="alice@example.com",
            reply_to_addr="alice@example.com",
            subject="Hello",
            body_text="Test email",
            body_html=None,
            urls=[],
            url_display_pairs=[],
            attachments=[],
            headers={
                "from": "Alice <alice@example.com>",
                "reply-to": "alice@example.com",
                "to": "Undisclosed recipients",
                "received": "server1\nserver2"
            },
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True
        )
        result: RuleHit = rule_headers_analyse(rec, CFG)
        self.assertFalse(result.passed)
        self.assertIn("undisclosed_recipients", result.details)
        self.assertEqual(result.score_delta, 0.5)

    def test_excessive_received_hops(self):
        """Test detection of excessive received hops."""
        rec = EmailRecord(
            from_display="Alice",
            from_addr="alice@example.com",
            reply_to_addr="alice@example.com",
            subject="Hello",
            body_text="Test email",
            body_html=None,
            urls=[],
            url_display_pairs=[],
            attachments=[],
            headers={
                "from": "Alice <alice@example.com>",
                "reply-to": "alice@example.com",
                "to": "bob@example.com",
                "received": "server1\nserver2\nserver3\nserver4\nserver5\nserver6"
            },
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True
        )
        result: RuleHit = rule_headers_analyse(rec, CFG)
        self.assertFalse(result.passed)
        self.assertIn("received_hops", result.details)
        self.assertEqual(result.score_delta, 0.3)

if __name__ == "__main__":
    unittest.main()