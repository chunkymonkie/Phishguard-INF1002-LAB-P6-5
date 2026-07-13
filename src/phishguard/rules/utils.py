from __future__ import annotations

import re
from typing import Iterable, Tuple, Dict, List

#==========================================
#           Regex Pattern Helpers         =
#==========================================

# Regex for IPv4 address validation
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#==========================================
#           Domain Utilities              =
#==========================================

def to_ascii_domain(domain: str) -> str:
    """
    Convert a domain to its ASCII representation using IDNA encoding.
    Handles internationalized domain names (IDN).
    """
    if not domain: 
        return ""
    d = domain.strip().rstrip(".").lower()
    try:
        return d.encode("idna").decode("ascii")
    except Exception:
        pass
    return d

def top_level_domain(labelled_domain: str) -> str:
    """
    Return top-level domain (last label), or ''.
    """
    parts = list(p for p in labelled_domain.strip().rstrip(".").split(".") if p)
    return parts[-1] if parts else ""

#==========================================
#           Email Utilities               =
#==========================================

def parse_email_domain(addr: str) -> str:
    """
    Extract the domain from an email address.
    Returns an empty string if the address is invalid.
    """
    if not addr or "@" not in addr:
        return ""
    return to_ascii_domain(addr.split("@", 1)[1])


#==========================================
#           URL Utilities                 =
#==========================================

def parse_url_host(url: str) -> str:
    """
    Extract the host from an HTTP(S) URL.
    Accepts 'http://', 'https://', and 'www.' prefixes.
    Strips user info and port if present.
    Returns the ASCII domain.
    """
    if not url:
        return ""
    strip_url = url.strip().lower()

    if strip_url.startswith('//'):
        strip_url = 'http:' + strip_url
    if strip_url.startswith('www.'):
        host = strip_url.split("/", 1)[0]
        return to_ascii_domain(host)
    if strip_url.startswith('https://'):
        host = strip_url[8:].split("/", 1)[0]
    elif strip_url.startswith('http://'):
        host = strip_url[7:].split("/", 1)[0]
    else:
        host = strip_url

    # Strip user info if present
    if "@" in host:
        host = host.split("@", 1)[1]

    # Strip port if present
    if ":" in host:
        host = host.split(":", 1)[0]
    return to_ascii_domain(host)

#==========================================
#           IP Address Utilities          =
#==========================================

def is_ipv4_host(host: str) -> bool:
    """
    Check if the given host is a valid IPv4 address.
    """
    if not host:
        return False
    return bool(_IPV4_RE.match(host))

#==========================================
#           Registrable Domain Helpers    =
#==========================================

def registrable_domain(domain: str, effective_tld: Iterable[str] = None) -> str:
    """
    Get the registrable domain (e.g., example.com, example.co.uk).
    Uses the effective TLD list to handle multi-label TLDs (like 'co.uk').
    Returns an empty string if the domain is invalid.
    """
    d = to_ascii_domain(domain)
    if not d or "." not in d:
        return d  # Return single label domains as-is
    
    parts = d.split(".")
    if len(parts) < 2:
        return d
    
    etld = {e.lower().lstrip(".") for e in (effective_tld or [])}
    
    # Check for multi-label TLDs (e.g., 'co.uk', 'com.sg')
    if len(parts) >= 3:
        two_label_tld = ".".join(parts[-2:])
        if two_label_tld in etld:
            return ".".join(parts[-3:])
    
    # Default to standard two-label registrable domain
    return ".".join(parts[-2:])

def same_registrable(domain1: str, domain2: str, effective_tld: Iterable[str]) -> bool:
    """
    Check if two domains share the same registrable domain.
    Useful for phishing detection and domain comparison.
    """
    return registrable_domain(domain1, effective_tld) == registrable_domain(domain2, effective_tld)

#==========================================
#           Lookalike Domain Helpers      =
#==========================================

def apply_lookalike_variants(s: str, pairs: Iterable[str]) -> str:
    """
    Normalize homograph and confusable character pairs.
    pairs: Iterable of strings in the format "char1:char2"
    We map the right side to the left side for normalization.
    This creates a canonical form where confusable characters are standardized.
    """
    if not s:
        return ""
    
    # Convert to lowercase first for consistent processing
    result = s.lower()
    
    confusables: List[Tuple[str, str]] = []
    for pair in pairs:
        if ':' in pair:
            left, right = pair.split(":", 1)
            left, right = left.strip().lower(), right.strip().lower()
            if left and right:
                confusables.append((left, right))
    
    # Sort by length of right side descending to handle multi-char sequences first
    confusables.sort(key=lambda x: len(x[1]), reverse=True)
    
    # Apply confusable mappings (right -> left)
    for left, right in confusables:
        result = result.replace(right, left)
    
    return result

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Simple Levenshtein edit distance implementation.
    """
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    # Ensure a is the shorter
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    previous = list(range(len(s1) + 1))
    for j, bj in enumerate(s2, 1):
        current = [j]
        for i, ai in enumerate(s1, 1):
            ins = previous[i] + 1
            dele = current[i - 1] + 1
            subs = previous[i - 1] + (0 if ai == bj else 1)
            current.append(min(ins, dele, subs))
        previous = current
    return previous[-1]



    
