import os
import sys
from typing import List, Tuple

# --- Path setup for importing project modules ---
# Ensure we can import from the project src directory (phishguard/src)
_TESTS_DIR = os.path.dirname(__file__)
_PROJECT_ROOT = os.path.abspath(os.path.join(_TESTS_DIR, '..'))
_SRC_DIR = os.path.join(_PROJECT_ROOT, 'src')
if _SRC_DIR not in sys.path:
    sys.path.append(_SRC_DIR)

# --- Import project classes ---
from phishguard.storage.storage import EmailReportManager
from phishguard.schema.classes import EmailRecord, RuleHit, Severity

# --- Helper to create an EmailReportManager for testing ---
def _make_manager(filename: str = "test_emailReport.csv") -> EmailReportManager:
    """Create a new EmailReportManager instance for testing."""
    return EmailReportManager(filename)

# --- Helper to generate example email records and rule hits ---
def _example_records() -> List[Tuple[EmailRecord, List[RuleHit]]]:
    """
    Returns a list of tuples, each containing an EmailRecord and a list of RuleHits.
    Used to populate the storage with test data.
    """
    examples: List[Tuple[EmailRecord, List[RuleHit]]] = []

    def mk_email(
        from_addr: str,
        subject: str,
        body_text: str,
        body_html: str = '',
    ) -> EmailRecord:
        """Helper to create an EmailRecord with minimal required fields."""
        return EmailRecord(
            from_display='',
            from_addr=from_addr,
            reply_to_addr=None,
            subject=subject,
            body_text=body_text,
            body_html=body_html or None,
            urls=[],
            url_display_pairs=[],
            attachments=[],
            headers={'x-test': 'true'},
            spf_pass=None,
            dkim_pass=None,
            dmarc_pass=None,
        )

    # Example: Obvious phishing with critical severity
    examples.append((
        mk_email(
            'phishing@fake-bank.com',
            'URGENT: Your account will be closed in 24 hours!',
            'Dear customer, we detected unusual activity. Verify your identity immediately to avoid permanent account closure. This is your FINAL warning.',
            '<p>Dear customer, we detected <strong>unusual activity</strong>. <a href="http://fake-verify.example">Verify now</a> to avoid closure.</p>'
        ),
        [RuleHit('keywords', passed=False, score_delta=50.0, severity=Severity.CRITICAL, details={'kw': 'URGENT'})]
    ))

    # Example: PII request with high severity
    examples.append((
        mk_email(
            'support@suspicious-site.org',
            'Update your payment information',
            'Your payment method was declined. Please update your credit card details and SSN to continue using our service.',
            '<p>Your payment method was declined. <a href="http://update-billing.example">Update billing</a> to continue.</p>'
        ),
        [RuleHit('pii_request', passed=False, score_delta=30.0, severity=Severity.HIGH, details={})]
    ))

    # Example: Urgency tactic with medium severity
    examples.append((
        mk_email(
            'admin@questionable-service.net',
            'Your subscription is about to expire',
            'Your subscription will expire in 48 hours. Renew now to prevent interruption of service.',
            ''
        ),
        [RuleHit('urgency', passed=False, score_delta=15.0, severity=Severity.MEDIUM, details={})]
    ))

    # Example: Legitimate newsletter (no rule hits)
    examples.append((
        mk_email(
            'newsletter@tech-news.com',
            'Weekly Technology Newsletter',
            'This week in tech: AI breakthroughs, security patches, and developer tools round-up.',
            ''
        ),
        []
    ))

    # Example: Legitimate bank statement (no rule hits)
    examples.append((
        mk_email(
            'noreply@legitimate-bank.com',
            'Monthly Statement Available',
            'Your monthly statement is now available. Log in to your online banking portal to view and download.',
            ''
        ),
        []
    ))

    return examples

# --- Test function for storage and JSON output ---
def test_storage_inserts_example_data_and_writes_json():
    """
    Test that example email records can be inserted into storage,
    and that a corresponding JSON file is created.
    """
    manager = _make_manager()

    before_count = len(manager.read_all_records())

    # Insert example records using EmailRecord + RuleHit
    inserted = 0
    for email, hits in _example_records():
        ok = manager.add_email_record(email, hits)
        if ok:
            inserted += 1

    # Also verify legacy call remains compatible
    manager.add_email_record('legacy@compat.test', 'Legacy path', 'Body unused', 'Low')
    inserted += 1

    records = manager.read_all_records()
    assert len(records) >= before_count + inserted

    # JSON should be created next to CSV
    json_path = manager.json_filename
    assert os.path.exists(json_path)

# --- Run test if executed as a script ---
if __name__ == "__main__":
    try:
        test_storage_inserts_example_data_and_writes_json()
        print("OK: example data inserted into CSV and JSON under outPutResult.")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
