from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

# =============================
# Data class for email record =
# =============================

@dataclass
class EmailRecord:
    """
    Represents a parsed email with relevant fields for phishing detection.
    """
    from_display: str                   # Display name of the sender
    from_addr: str                      # Email address of the sender
    reply_to_addr: Optional[str]        # Reply-To email address (if any)
    subject: str                        # Subject of the email
    body_text: str                      # Plain text body of the email
    body_html: Optional[str]            # HTML body of the email (if any)
    urls: List[str]                     # List of URLs found in the email
    url_display_pairs: List[Tuple[str, str]] # List of (display text, URL) pairs
    attachments: List[str]              # List of attachment filenames
    headers: Dict[str, str]             # Dictionary of email headers
    spf_pass: Optional[bool]            # SPF authentication result
    dkim_pass: Optional[bool]           # DKIM authentication result
    dmarc_pass: Optional[bool]          # DMARC authentication result

# ==========================
# Enum for severity levels =
# ==========================

class Severity(Enum):
    """
    Represents severity levels for rule hits.
    """
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

# =========================
# Data class for rule hit =
# =========================

@dataclass
class RuleHit:
    """
    Represents the result of applying a detection rule to an email.
    """
    rule_name: str                      # Name of the rule
    passed: bool                        # True if rule did NOT match anything suspicious, False otherwise
    score_delta: float                  # Score impact of this rule
    severity: Severity                  # Severity level of the rule hit
    details: Dict[str, str]             # Additional details about the rule hit