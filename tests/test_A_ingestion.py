import unittest
from phishguard.ingestion.loaders import iterate_emails

class TestEmailIngestion(unittest.TestCase):
    def test_iter_messages_single_file(self):
        origin, msg = next(iterate_emails("tests/samples/ham.7c53336b37003a9286aba55d2945844c"))
        self.assertIn("Subject", msg)

    def test_iter_messages_dir(self):
        msgs = list(iterate_emails("tests/samples/spam"))
        self.assertGreater(len(msgs), 0)

if __name__ == "__main__":
    unittest.main()