import unittest
from phishguard.schema import EmailRecord
from phishguard.rules.url_redflags import rule_urlredflags
from phishguard.config import load_config

# Base email record used as a template for test cases
BASE_REC = EmailRecord(
    from_display="Support",
    from_addr="support@example.com",
    reply_to_addr=None,
    subject="Hello",
    body_text="This is a benign message.",
    body_html=None,
    urls=[], url_display_pairs=[], attachments=[], headers={},
    spf_pass=None, dkim_pass=None, dmarc_pass=None
)

# Load configuration for URL red flag detection
CFG = load_config()


class TestUrlDetection(unittest.TestCase):
    def test_ipaddr_in_url(self):
        """
        TestCase: Detects if an IP address is used in the URL.
        Should flag as suspicious (score 1.5), but not for normal domains (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.google.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://172.217.16.142/"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_pos.score_delta, 1.5)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_at_symbol(self):
        """
        TestCase: Detects '@' symbol in the netloc of the URL.
        Should flag as suspicious (score 1.5), but not for normal domains (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.facebook.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://www.google.com@malicious.com"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_pos.score_delta, 1.5)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_subdomain_limit(self):
        """
        TestCase: Detects URLs with more than 3 subdomains.
        Should flag as suspicious (score 2.0), but not for normal subdomains (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://mail.google.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://login.paypal.com.secure.verify.example.com"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_pos.score_delta, 2.0)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_shorten_domain(self):
        """
        TestCase: Detects shortened URLs (e.g., bit.ly) as suspicious.
        Should flag as suspicious (score 1.5), but not for normal domains (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.amazon.com/product/12345"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://bit.ly/3xYzAbC"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_pos.score_delta, 1.5)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_suspicious_path(self):
        """
        TestCase: Detects suspicious keywords in the URL path (e.g., 'login', 'verify').
        Should flag as suspicious (score 1.0), but not for normal paths (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.wikipedia.org/wiki/Python"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://secure-paypal.com/login/verify"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_pos.score_delta, 1.0)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_suspicious_tld(self):
        """
        TestCase: Detects suspicious top-level domains (TLDs), e.g., '.xyz'.
        Should flag as suspicious (score 1.0), but not for common TLDs (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.microsoft.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://secure-login.xyz"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_pos.score_delta, 1.0)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_combined_phishing(self):
        """
        TestCase: Combination of multiple suspicious features in a single URL.
        Should sum all relevant scores (expected: 5.5).
        """
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://192.168.0.1@bit.ly/login"]})
        hit_pos = rule_urlredflags(rec_phish, CFG)
        self.assertEqual(hit_pos.score_delta, 5.5)

    def test_legitimate_complex(self):
        """
        TestCase: Complex but legitimate URL.
        Should not be flagged (score 0.0).
        """
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://shop.amazon.co.uk/product/12345"]})
        hit_neg = rule_urlredflags(rec_legit, CFG)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_edge_cases(self):
        """
        TestCase: Edge cases where URLs may look suspicious but are legitimate.
        Should not be flagged (score 0.0).
        """
        legit1 = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://example.com/path?user=name@example.com"]})
        legit2 = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.example.tech"]})
        hit1 = rule_urlredflags(legit1, CFG)
        hit2 = rule_urlredflags(legit2, CFG)
        self.assertEqual(hit1.score_delta, 0.0)
        self.assertEqual(hit2.score_delta, 0.0)


if __name__ == "__main__":
    unittest.main()
