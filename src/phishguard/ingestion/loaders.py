from __future__ import annotations

import os
import mailbox
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Generator, Tuple

PathLike = str | Path

class IngestionError(Exception):
    """Raised when ingestion of email fails"""

#==========================================
#         Email Parsing Helpers           =
#==========================================

def _parse_single_email(path: Path) -> EmailMessage:
    """
    Parse a single email file and return an EmailMessage object.
    Tries standard parsing first, then falls back to mbox parsing if needed.
    Raises IngestionError if parsing fails.
    """
    if not path.is_file():
        raise IngestionError(f"File not found: {path}")
    try:
        with path.open('rb') as file:
            return BytesParser(policy=policy.default).parse(file)
    except Exception:
        # Fallback: try parsing as mbox message if file starts with 'From '
        raw = path.read_bytes()
        if raw.startswith(b'From '):
            try:
                return mailbox.mboxMessage(raw, policy=policy.default)
            except Exception as e:
                raise IngestionError(f"Failed to parse mbox message from {path}: {e}")
        raise IngestionError(f"Failed to parse email from {path}")

#==========================================
#         Mbox Parsing Helpers            =
#==========================================

def _parse_mbox(path: Path) -> Generator[Tuple[Path, EmailMessage], None, None]:
    """
    Parse an mbox file and yield (Path, EmailMessage) tuples for each message.
    Skips messages that cannot be parsed.
    """
    if not path.is_file():
        raise IngestionError(f"Mbox file not found: {path}")
    try:
        mbox = mailbox.mbox(path, factory=lambda f: BytesParser(policy=policy.default).parse(f))
    except Exception as e:
        raise IngestionError(f"Failed to open mbox file {path}: {e}")
    for i, msg in enumerate(mbox):
        if not isinstance(msg, EmailMessage):
            # Try to re-parse as EmailMessage if needed
            raw = msg.as_bytes()
            try:
                msg = BytesParser(policy=policy.default).parsebytes(raw)
            except Exception as e:
                print(f"Skipping message {i+1} in {path} due to parse error: {e}")
                continue
        # Yield a synthetic path for each message in the mbox
        yield path.with_name(f"{path.name}::msg{i+1}"), msg

#==========================================
#      File or Mbox Dispatch Helper       =
#==========================================

def _parse_file_or_mbox(path: Path) -> Generator[Tuple[Path, EmailMessage], None, None]:
    """
    Try to parse a file as a single email; if that fails, try as an mbox.
    Yields (Path, EmailMessage) tuples.
    """
    try:
        yield path, _parse_single_email(path)
        return
    except IngestionError:
        # If not a single email, try as mbox
        yield from _parse_mbox(path)
    return

#==========================================
#         Email Iteration Helper          =
#==========================================

def iterate_emails(source: PathLike) -> Generator[Tuple[Path, EmailMessage], None, None]:
    """
    Iterate over all emails in a file or directory.
    Yields (Path, EmailMessage) tuples for each email found.
    Skips files that cannot be parsed as emails.
    """
    p = Path(source)
    if p.is_file():
        yield from _parse_file_or_mbox(p)
    elif p.is_dir():
        walker = os.walk(p)
        for dirpath, _dirnames, filenames in walker:
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if not fpath.is_file():
                    continue
                try:
                    yield from _parse_file_or_mbox(fpath)
                except IngestionError as e:
                    print(f"Skipping {fpath}: {e}")
                    continue
        return
    else:
        raise IngestionError(f"Path is neither file nor directory: {source}")
