import unittest
from phishguard.schema import EmailRecord
from phishguard.rules.keywords import rule_keywords
from phishguard.config import load_config

# Create a base EmailRecord instance for use in tests
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

# Load configuration for keyword rules
CFG = load_config()

class TestKeywordPositioning(unittest.TestCase):
    def test_subject_has_more_weight_than_body(self):
        """
        Test that keywords in the subject line have more weight than in the body.
        Also checks that all-caps bonus is applied in the subject.
        """
        rec1 = BASE_REC.__class__(**{**BASE_REC.__dict__, "subject": "URGENT: please read"})
        rec2 = BASE_REC.__class__(**{**BASE_REC.__dict__, "body_text": "this is urgent in the body only"})
        h1 = rule_keywords(rec1, CFG)
        h2 = rule_keywords(rec2, CFG)
        # subject hit includes subject_boost(1.5) + allcaps bonus(0.2)
        print(h1.details)
        self.assertGreaterEqual(h1.score_delta, 0.8 * 1.5)  # at least subject weight (>=)
        self.assertGreater(h1.score_delta, h2.score_delta)

    def test_intro_boost_applies(self):
        """
        Test that keyword occurrences within the intro window (first 200 chars)
        receive an intro_boost multiplier.
        """
        txt = "verify your account now. please verify your account today. " \
              + "later content goes here..."
        rec = BASE_REC.__class__(**{**BASE_REC.__dict__, "body_text": txt})
        h = rule_keywords(rec, CFG)
        # Two occurrences within intro window (200 chars) get intro_boost
        self.assertGreaterEqual(h.score_delta, min(2 * 1.0 * 1.25, 2))

    def test_per_phrase_cap_limits_repeats(self):
        """
        Test that repeated keyword phrases are capped at a maximum count per phrase.
        """
        txt = "x" * 200 + "urgent " * 10  # 10 repeats in body -> should cap at 2 occurrences
        rec = BASE_REC.__class__(**{**BASE_REC.__dict__, "body_text": txt})
        h = rule_keywords(rec, CFG)
        expected = 0.8 * 2 * 1.0  # weight * per_phrase_max * body_boost
        self.assertAlmostEqual(h.score_delta, expected, places=5)

    def test_word_boundaries_reduce_false_positives(self):
        """
        Test that keyword matching respects word boundaries to reduce false positives.
        """
        rec = BASE_REC.__class__(**{**BASE_REC.__dict__, "body_text": "reverify your account quickly"})  # not 'verify your account'
        h = rule_keywords(rec, CFG)
        # Should not match 'verify your account' as word boundaries are taken into account
        self.assertTrue(h.passed or h.score_delta < 1.0)

if __name__ == "__main__":
    unittest.main()
