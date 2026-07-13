import os
import tempfile
import unittest
from pathlib import Path
from email.message import EmailMessage
from email.generator import BytesGenerator
from io import BytesIO

from phishguard.ingestion.loaders import iterate_emails


def _write_eml(path: Path, subject="Hello", body="Plain body"):
    msg = EmailMessage()
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "Bob <bob@example.com>"
    msg["Subject"] = subject
    msg.set_content(body)
    with open(path, "wb") as f:
        BytesGenerator(f).flatten(msg)


def _write_mbox(path: Path):
    # Minimal mbox with 2 messages using Unix "From " separators
    def _eml_bytes(subj):
        m = EmailMessage()
        m["From"] = "Carol <carol@example.com>"
        m["To"] = "Dave <dave@example.com>"
        m["Subject"] = subj
        m.set_content("Body for " + subj)
        buf = BytesIO()
        BytesGenerator(buf).flatten(m)
        return buf.getvalue()

    with open(path, "wb") as f:
        for i in range(2):
            f.write(b"From carol@example.com Thu Jan 01 00:00:00 2025\n")
            f.write(_eml_bytes(f"Msg {i+1}"))
            if i == 0:
                f.write(b"\n")  # separator between messages


class TestIngestion(unittest.TestCase):
    def test_iter_messages_single_file(self):
        """
        This test creates a single .eml file with a specific subject ("Single") using _write_eml. 
        It then uses iterate_emails to parse the file and checks that the parsed email's subject contains "Single". 
        This verifies that the loader can correctly handle and parse a single email file.
        """
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "single.eml"
            _write_eml(p, subject="Single")
            origin, msg = next(iterate_emails(p))
            self.assertIn("Single", msg["Subject"])

    def test_iter_messages_dir(self):
        """
        This test creates a temporary directory and writes two .eml files with different subjects ("A" and "B"). 
        It then uses iterate_emails on the directory and collects all parsed subjects. 
        The test asserts that both "A" and "B" are present, ensuring that the loader 
        can iterate over and parse all email files in a directory.
        """
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "a.eml"; _write_eml(p1, subject="A")
            p2 = Path(td) / "b.eml"; _write_eml(p2, subject="B")
            msgs = list(iterate_emails(td))
            subjects = {m["Subject"] for _, m in msgs}
            self.assertTrue({"A", "B"}.issubset(subjects))

    def test_strip_unix_from_line_single_saved_email(self):
        """
        This test creates a single .eml file that starts with a Unix "From " 
        line (a common mbox separator), followed by a normal email message. 
        It parses the file and checks that the subject is correctly read as "Odd". 
        This ensures that the loader can handle and ignore a leading "From " line 
        in single email files, not just in mbox files
        """
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "odd.eml"
            msg = EmailMessage()
            msg["From"] = "X <x@ex.com>"
            msg["To"] = "Y <y@ex.com>"
            msg["Subject"] = "Odd"
            msg.set_content("Hi")
            buf = BytesIO(); BytesGenerator(buf).flatten(msg)
            with open(p, "wb") as f:
                f.write(b"From x@ex.com Thu Jan 01 00:00:00 2025\n")
                f.write(buf.getvalue())
            origin, parsed = next(iterate_emails(p))
            self.assertEqual(parsed["Subject"], "Odd")


if __name__ == "__main__":
    unittest.main()
