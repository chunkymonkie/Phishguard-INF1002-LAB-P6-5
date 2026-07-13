import os
import sys
import unittest
from copy import deepcopy
from typing import Dict

# --- Setup import paths so we can import from src/ ---
_TESTS_DIR = os.path.dirname(__file__)
_PROJECT_ROOT = os.path.abspath(os.path.join(_TESTS_DIR, '..'))
_SRC_DIR = os.path.join(_PROJECT_ROOT, 'src')
if _SRC_DIR not in sys.path:
    sys.path.append(_SRC_DIR)

# --- Import modules from the main project ---
from phishguard.scoring.aggregate import evaluate_email
from phishguard.schema import EmailRecord, RuleHit, Severity


# --- Base email record used for all tests ---
BASE_REC = EmailRecord(
    from_display="Support",
    from_addr="support@nus.edu.sg",
    reply_to_addr=None,
    subject="Hello",
    body_text="This is a benign message.",
    body_html=None,
    urls=[],
    url_display_pairs=[],
    attachments=[],
    headers={},
    spf_pass=None,
    dkim_pass=None,
    dmarc_pass=None,
)

# --- Thresholds for scoring ---
TEST_THRESHOLDS = {"safe_max": 20, "phishing_min": 40}


def get_test_config():
    """Return config dictionary passed to evaluate_email()"""
    return {"thresholds": TEST_THRESHOLDS}


# --- Example rules ---
def rule_keyword(email: EmailRecord, config: Dict) -> RuleHit:
    """Checks if the subject contains 'URGENT'."""
    if "URGENT" in email.subject:
        return RuleHit(
            rule_name="keywords",
            passed=False,
            score_delta=20.0,
            severity=Severity.CRITICAL,
            details={"kw": "URGENT"},
        )
    return RuleHit(
        rule_name="keywords",
        passed=True,
        score_delta=0,
        severity=Severity.LOW,
        details={},
    )


def rule_phirequest(email: EmailRecord, config: Dict) -> RuleHit:
    """Checks if the email body requests sensitive info like SSN or credit card."""
    if "SSN" in email.body_text or "credit card" in email.body_text:
        return RuleHit(
            rule_name="phi_request",
            passed=False,
            score_delta=30.0,
            severity=Severity.HIGH,
            details={},
        )
    return RuleHit(
        rule_name="phi_request",
        passed=True,
        score_delta=0,
        severity=Severity.LOW,
        details={},
    )


# --- Unit test class ---
class TestAggregateEvaluate(unittest.TestCase):

    def setUp(self):
        """Prepare common setup for all tests."""
        self.rules = [rule_keyword, rule_phirequest]
        self.config = get_test_config()

    def test_safe_email(self):
        """Benign email should be labeled 'Safe'."""
        email = deepcopy(BASE_REC)
        email.subject = "Weekly Newsletter"
        email.body_text = "Nothing malicious here."

        hits, total_score, label = evaluate_email(email, self.rules, self.config)

        self.assertEqual(total_score, 0)
        self.assertEqual(label, "Safe")
        self.assertTrue(all(hit.passed for hit in hits))

    def test_suspicious_email(self):
        """Email that triggers one rule should be labeled 'Unknown'."""
        email = deepcopy(BASE_REC)
        email.subject = "Update your payment info"
        email.body_text = "Please provide your credit card to continue."

        hits, total_score, label = evaluate_email(email, self.rules, self.config)

        self.assertEqual(total_score, 30)
        self.assertEqual(label, "Unknown")
        self.assertTrue(hits[0].passed)
        self.assertFalse(hits[1].passed)

    def test_phishing_email(self):
        """Email that triggers both rules should be labeled 'Phishing'."""
        email = deepcopy(BASE_REC)
        email.subject = "URGENT: Account closing!"
        email.body_text = "Verify your identity now. Provide your SSN."

        hits, total_score, label = evaluate_email(email, self.rules, self.config)

        self.assertEqual(total_score, 50)
        self.assertEqual(label, "Phishing")
        self.assertFalse(hits[0].passed)
        self.assertFalse(hits[1].passed)


if __name__ == "__main__":
    unittest.main()
