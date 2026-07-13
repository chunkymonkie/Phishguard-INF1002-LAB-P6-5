import sys
import json 
import csv
import unittest
from pathlib import Path

# Set up paths to ensure the src directory is importable
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

from phishguard.reporting import writers

# Sample data to be used in tests
sample = [
    {
        "file_path": "emails/test1.eml",
        "from_addr": "phisher@fake.com",
        "subject": "Win a prize!",
        "classification": "phishing",
        "total_score": 20,
        "rule_hits": [
            {"rule_name": "Suspicious Link", "passed": False},
            {"rule_name": "Urgent Language", "passed": True},
        ],
    }
]

# Permanent output folder for test results
output_dir = Path(__file__).parent / "output"
output_dir.mkdir(exist_ok=True)

class TestWriters(unittest.TestCase):
    """Unit tests for phishguard.reporting.writers"""

    def test_json(self):
        """Test writing results in JSON format and validate output."""
        output_file = output_dir / "sample_results.json"
        json_results = writers.write_results(sample, str(output_file), format="json")

        self.assertTrue(json_results)
        self.assertTrue(output_file.exists())

        data = json.loads(output_file.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["total_emails"], 1)

    def test_writecsv(self):
        """Test writing results in CSV format and validate output."""
        output_file = output_dir / "sample.csv"
        csv_results = writers.write_results(sample, str(output_file), format="csv")

        self.assertTrue(csv_results)
        self.assertTrue(output_file.exists())

        rows = list(csv.DictReader(output_file.open(encoding="utf-8")))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["classification"], "phishing")

    def test_auto_detect_format(self):
        """Ensure auto format detection works for both JSON and CSV."""
        json_file = output_dir / "auto_results.json"
        csv_file = output_dir / "auto_results.csv"

        self.assertTrue(writers.write_results(sample, str(json_file), format="auto"))
        self.assertTrue(writers.write_results(sample, str(csv_file), format="auto"))

        self.assertTrue(json_file.exists())
        self.assertTrue(csv_file.exists())


if __name__ == "__main__":
    unittest.main()