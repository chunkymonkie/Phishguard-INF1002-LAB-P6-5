from __future__ import annotations

from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple
import html
import re

#==========================================
#          URL Extracting Helpers         =
#==========================================

# Plaintext URL Extractor
_URL_RE = re.compile(r"""
    \b
    (?:
        https?://
    )
    [^\s<>"']+""", re.VERBOSE | re.IGNORECASE
)

# A Tag Extractor
_A_HREF_RE = re.compile(r'(?is)<a[^>]*\bhref\s*=\s*([\'"])(?P<href>.+?)\1[^>]*>(?P<label>.*?)</a>')

# Base URL Extractor
_BASE_RE = re.compile(r'(?is)<base[^>]*\bhref\s*=\s*([\'"])(?P<href>.+?)\1')

def _strip_html_tags(string: str) -> str:
    return re.sub(r'<[^>]+>', '', string).strip()

def _strip_url(url: str) -> Tuple[str, str, str]:
    """
        Returns scheme, host, path+query+fragment.
        Only supports http and https schemes.
    """

    url_match = re.match(r'^(https?)://([^/]+)(/.*)?$', url, re.IGNORECASE)
    if not url_match:
        return '', '', ''
    scheme = url_match.group(1).lower()
    host = url_match.group(2).lower()
    rest = url_match.group(3) or '/'
    return scheme, host, rest

def _simple_join(base: str, href: str) -> str:
    """
        Joiner for HTML hrefs with a base URL.
         - If href is absolute, return it as is.
         - If href starts with '/', join with base's scheme and host.
         - If href starts with '//', assume 'http:' scheme and join with host.
         - Otherwise, join with base's scheme, host, and path.
    """
    
    if not href:
        return href
    href = href.strip()
    if re.match(r'^(?:https?)://', href, re.IGNORECASE):
        return href
    if href.startswith('//'):
        return 'http:' + href
    
    base_scheme, base_host, base_rest = _strip_url(base)
    if not base_scheme or not base_host:
        return href
    
    if href.startswith('/'):
        return f'{base_scheme}://{base_host}{href}'
    
    # Relative path
    if '/' in base_rest:
        base_path = base_rest.rsplit('/', 1)[0]
    else:
        base_path = ''
    if base_path and not base_path.endswith('/'):
        base_path += '/'
    return f'{base_scheme}://{base_host}{base_path}{href}'

def _normalize_url(url: str) -> str:
    """
        Normalize punctuation in URLs and 'www.' without scheme.
    """
    url = url.strip().strip(").,;:")
    if url.startswith('www.'):
        url = 'http://' + url
    return url

#===========================================
#          URL and pair Extracting         =
#===========================================

def extract_urls(body_text: str, body_html: Optional[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
        Return URLs and URL display pairs from body text and HTML.
        URLs are normalized and deduplicated.
        URL display pairs are (displayed_text, actual_url) tuples.
    """
    urls: List[str] =[]
    url_pairs: List[Tuple[str, str]] = []

    # Extract from body text
    for url_match in _URL_RE.finditer(body_text):
        url = _normalize_url(url_match.group(0))
        if url not in urls:
            urls.append(url)
    
    # Extract from body HTML
    base = ''
    if body_html:
        base_match = _BASE_RE.search(body_html)
        if base_match:
            base = _normalize_url(html.unescape(base_match.group('href').strip()))
        
        for a_match in _A_HREF_RE.finditer(body_html):
            href = html.unescape(a_match.group('href').strip())
            label = html.unescape(a_match.group('label').strip() or '')
            # Abosolutize href with base if present
            href_abs = _simple_join(base, href) if base else href
            label_text = _strip_html_tags(label)
            if (label_text and href_abs) not in url_pairs:
                url_pairs.append((label_text, href_abs))
            # Also add href to urls if not already present
            href_norm = _normalize_url(href_abs)
            if href_norm and href_norm not in urls:
                urls.append(href_norm)

    return urls, url_pairs


#====================================================
#           Convenient URL Pair Extracting          =
#====================================================

def extract_url_pairs(body_html: Optional[str]) -> List[Tuple[str, str]]:
    """
        Convenience function to extract URL display pairs from HTML content only.
    """
    if not body_html:
        return []
    _, url_pairs = extract_urls('', body_html)
    return url_pairs


#====================================================
#           Attachment Extracting                   =
#====================================================

def extract_attachments(msg: EmailMessage) -> List[str]:
    """
        Return a list of attachment filenames in lowercase.
    """
    attachments: List[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename and str(filename).strip().lower() not in attachments:
            attachments.append(str(filename).strip().lower())
            
    return attachments

