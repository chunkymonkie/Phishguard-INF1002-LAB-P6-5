import unittest
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.rules.lookalike_domain import rule_lookalike_domain
from phishguard.config import load_config

BASE_REC = EmailRecord(
    from_display="Support",
    from_addr="support@unknown.tld",
    reply_to_addr=None,
    subject="Hello",
    body_text="See https://example.com",
    body_html=None,
    urls=["https://example.com"],
    url_display_pairs=[],
    attachments=[],
    headers={},
    spf_pass=None, dkim_pass=None, dmarc_pass=None
)

CFG = load_config()

def rec_from(addr: str, urls=None):
    r = BASE_REC
    return r.__class__(**{**r.__dict__, "from_addr": addr, "urls": urls or []})

class TestLookalike(unittest.TestCase):
    def test_exact_match_neutral(self):
        """
        Tests that legitimate domains from protected list are treated as trusted.
        When sender domain exactly matches a protected domain, no phishing is detected.
        This validates that legitimate emails from real PayPal don't get flagged.
        Expected: passed=True, score_delta=0.0, no penalty applied
        """
        hit = rule_lookalike_domain(rec_from("alert@paypal.com"), CFG)
        print(hit)
        self.assertTrue(hit.passed)
        self.assertEqual(hit.score_delta, 0.0)

    def test_distance_one_sender(self):
        """
        Tests detection of domains with single character difference after confusables normalization.
        Uses 'X' instead of 'l' in paypal.com, which creates edit distance 1 after normalization.
        This catches typosquatting attacks where attackers use similar but non-confusable characters.
        Expected: passed=False, score_delta>=2.5, HIGH severity, note="distance_1"
        """
        # Use a character substitution that creates edit distance 1 after normalization
        hit = rule_lookalike_domain(rec_from("alert@paypaX.com"), CFG)  # X instead of l
        print(f"Test distance one: {hit}")
        self.assertFalse(hit.passed)
        self.assertGreaterEqual(hit.score_delta, 2.5)
        self.assertIn(hit.severity.name, ("HIGH","CRITICAL"))

    def test_tld_swap_penalty(self):
        """
        Tests detection of TLD swapping attacks where same domain uses different TLD.
        Uses paypal.co instead of paypal.com - same second-level domain but different TLD.
        This catches attacks where criminals register similar domains with alternate TLDs.
        Expected: passed=False, score_delta>=1.0, note="tld_swap", MEDIUM severity
        """
        hit = rule_lookalike_domain(rec_from("team@paypal.co"), CFG)
        print(hit)
        self.assertFalse(hit.passed)
        self.assertGreaterEqual(hit.score_delta, 1.0)

    def test_confusables_normalization(self):
        """
        Tests detection of homograph attacks using visually confusable characters.
        Uses capital 'I' instead of lowercase 'l' in paypal.com (paypaI.com vs paypal.com).
        This is the core homograph attack detection - catches visual deception attempts.
        The algorithm detects confusable character substitutions before normalization occurs.
        Expected: passed=False, score_delta>=2.0, HIGH severity, note="homograph_attack"
        """
        # Test that confusable characters are detected as homograph attacks
        hit = rule_lookalike_domain(rec_from("alert@paypaI.com"), CFG)  # I instead of l
        print(f"Confusables test: {hit}")
        self.assertFalse(hit.passed)  # Should fail because I->l is detected as homograph attack
        self.assertGreaterEqual(hit.score_delta, 2.0)
        self.assertEqual(hit.details.get("note"), "homograph_attack")

    def test_url_host_checked(self):
        """
        Tests that lookalike detection analyzes URLs within email body, not just sender domain.
        Email comes from unknown sender but contains suspicious URL with lookalike domain.
        This validates that phishing links in email content are detected even when sender looks benign.
        Uses paypaX.com in URL which has edit distance 1 from protected paypal.com.
        Expected: passed=False, score_delta>=2.5, HIGH severity, kind="url"
        """
        hit = rule_lookalike_domain(rec_from("a@unknown.tld", urls=["http://paypaX.com/login"]), CFG)
        print(hit)
        self.assertFalse(hit.passed)
        self.assertGreaterEqual(hit.score_delta, 2.5)

if __name__ == "__main__":
    unittest.main()
