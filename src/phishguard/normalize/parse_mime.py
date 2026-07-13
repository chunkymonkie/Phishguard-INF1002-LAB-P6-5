from __future__ import annotations

from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import getaddresses
from typing import List, Optional, Tuple, Dict
import html
import re
import unicodedata

#====================================
#          Unicode Helper           =
#====================================

def _to_unicode(header_value: str | bytes) -> str:
    """
        Decode email header in string or bytes to a unicode string.
        Handles both bytes and str input, normalizes to NFC.
    """

    if isinstance(header_value, bytes):
        # Try decoding as UTF-8, fallback to latin1 if that fails
        try:
            clean_header = header_value.decode('utf-8', errors='replace')
        except Exception:
            clean_header = header_value.decode('latin1', errors='replace')
        return unicodedata.normalize('NFC', clean_header)
    
    else:
        # Decode header using email.header utilities
        try:
            clean_header = str(make_header(decode_header(header_value)))
        except Exception:
            clean_header = header_value
    return unicodedata.normalize('NFC', clean_header)


#====================================
#          Header Decoding          =
#====================================

def normalize_header(msg: EmailMessage) -> Dict[str, str]:
    """
        Return a dictionary of decoded key headers. 
        If multiple 'received' headers exist, combine them into a single string.
    """
    
    multi_header = {'received'}  # Headers that can appear multiple times
    key_headers = ["subject", "from", "reply-to", "return-path", "received","to"]

    output: Dict[str, str] = {}
    for key in key_headers:
        header_value: List[str] = []
        # Collect all values for the header (handles multi-valued headers)
        for value in msg.get_all(key) or []:
            header_value.append(_to_unicode(value))
        if not header_value:
            continue
        # Join multiple values for multi_header, else take the first
        output[key] = '\n'.join(header_value) if key in multi_header else header_value[0]
    return output


#====================================
#          Address Decoding         =
#====================================

def _display_and_addr(addresses: List[Tuple[str, str]]) -> Tuple[str, Optional[str]]:
    """
        Decode display name and email address from a list of (display, address) tuples.
        Returns the first address found, or empty if none.
    """
    if not addresses:
        return '', None
    display_name, email_addr = addresses[0]
    return _to_unicode(display_name), email_addr.strip().lower() if email_addr else None

def decode_address(msg: EmailMessage) -> Tuple[str, str, Optional[str]]:
    """
        Decode from_display, from_addr, reply_to_addr from email headers.
        If 'From' header is missing, return empty string.
    """

    from_raw = msg.get("from", "")
    return_to_raw = msg.get("reply-to", "")
    from_display, from_addr = _display_and_addr(getaddresses([from_raw]))
    return_display, return_addr = _display_and_addr(getaddresses([return_to_raw]))

    return from_display, from_addr or '', return_addr or ''

#====================================
#          Body Extracting          =
#====================================

# Regular expressions for HTML tag and whitespace handling
_TAG_RE = re.compile(r'<[^>]+>')
_WS_RE = re.compile(r'[ \t\r\f\v]+')
_BR_RE = re.compile(r'(?i)<\s*br\s*/?\s*>')
_BLOCK_RE = re.compile(r'(?i)</\s*(p|div|h[1-6]|li|ul|ol|table|tr|td)\s*>')

def _html_to_text(html_content: str) -> str:
    """
        Convert HTML to plain text in the event there is no text/plain part.
        Handles <br> and block tags as line breaks, strips all other tags.
    """

    text = html_content
    text = _BR_RE.sub('\n', text)  # Replace <br> with newlines
    text = _BLOCK_RE.sub('\n', text)  # Replace block-level closing tags with newlines
    text = _TAG_RE.sub('', text)  # Remove all other HTML tags
    text = html.unescape(text)  # Unescape HTML entities
    lines = [line.strip() for line in text.splitlines()]
    s = '\n'.join(line for line in lines if line)
    s = _WS_RE.sub(' ', s)  # Normalize whitespace

    return s.strip()

def extract_body(msg: EmailMessage) -> Tuple[str, Optional[str]]:
    """
        Returns body_text or body_html from email message.
        Prefers text/plain over text/html if both are available.
        If only HTML is present, converts it to plain text.
    """

    plain_texts: List[str] = []
    html_texts: Optional[str] = None

    if msg.is_multipart():
        # Walk through all parts of the email
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = (part.get_content_type() or "").lower()
            if content_type == "text/plain":
                # Try to get plain text content
                try:
                    plain_texts.append(part.get_content().strip())
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        plain_texts.append(payload.decode(part.get_content_charset('utf-8') or 'utf-8', errors='replace'))
            elif content_type == "text/html" and html_texts is None:
                # Try to get HTML content (only first occurrence)
                try:
                    html_texts = part.get_content().strip()
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_texts = payload.decode(part.get_content_charset('utf-8') or 'utf-8', errors='replace')
    else:
        # Single-part message
        content_type = (msg.get_content_type() or "").lower()
        if content_type == "text/plain":
            try:
                plain_texts.append(msg.get_content().strip())
            except Exception:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset('utf-8') or 'utf-8'
                    if charset.lower() == 'unknown-8bit':
                        charset = 'utf-8'
                    try:
                        plain_texts.append(payload.decode(charset or "utf-8", errors="replace"))
                    except LookupError:
                        # Fallback if charset is invalid (like "default")
                        plain_texts.append(payload.decode("utf-8", errors="replace"))

        elif content_type == "text/html" and html_texts is None:
            try:
                html_texts = msg.get_content().strip()
            except Exception:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    try:
                        html_texts = payload.decode(charset, errors='replace')
                    except LookupError:
                        html_texts = payload.decode('utf-8', errors='replace')
    
    # Prefer plain text, fallback to HTML converted to text
    body_text = '\n'.join(plain.strip() for plain in plain_texts if plain.strip())
    if not body_text and html_texts:
        body_text = _html_to_text(html_texts)
    return body_text, html_texts

