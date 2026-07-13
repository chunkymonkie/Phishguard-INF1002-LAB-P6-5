import re
from typing import List, Dict
from urllib.parse import urlparse
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.config import load_config

#==========================================
#           URL Feature Analysis          =
#==========================================

## This function will be used in detect_urlredflags() below:
def analyze_url_features(url, cfg):
    """
    Analyze and identify features of the given URL.
    Features checked:
      - IP addresses in domain
      - Presence of '@' symbol
      - Number of subdomains
      - Use of known URL shorteners
      - Suspicious keywords in URL path
      - Suspicious TLDs
    Returns a dictionary of feature flags.
    """
    urlnetloc: str = urlparse(url).netloc
    sus_keyword: List[str] = cfg.get("suspicious_keyword_path")
    sus_tlds: List[str] = cfg.get("suspicious_tlds")
    shortener_domains: List[str] = cfg.get("shortener_domains")
    tld_in_url: str = (urlnetloc.split("."))[-1]
    url_path: str = urlparse(url.lower()).path
    urlnetloc_split_at: List[str] = re.sub(r"^www\.", "", urlnetloc).split("@") # splits url if there is @

    # Features contains a dictionary with the key:value pair as shown:
    features = {
        # Checks for IP address in the domain part of the URL
        "has_ip_address": bool(any(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", part) for part in urlnetloc.split("@") or "")),
        # Checks for '@' symbol in the domain
        "has_at_symbol": "@" in urlnetloc,
        # Counts subdomains (naive: total dots minus 2)
        "num_subdomains": len(re.sub(r"^www\.", "", urlnetloc).split(".")) - 2 if url else 0,
        # Checks if domain is a known shortener
        "has_shortened_domain": any(part.lower() in shortener_domains for part in urlnetloc_split_at),
        # Checks for suspicious keywords in the path
        "suspicious_keyword_path": any(
            keyword in url_path for keyword in sus_keyword),
        # Checks for suspicious TLDs
        "suspicious_tlds": any(
            keyword in tld_in_url for keyword in sus_tlds),
    }

    # Returns the dictionary of features to detect_urlredflags()
    return features

#==========================================
#         URL Red Flags Detection         =
#==========================================

## Detects suspicious URL features
def rule_urlredflags(rec: EmailRecord, config: Dict):
    """
    Takes list of URL(s) in EmailRecord -> url_lists, and detects for suspicious features in the URL(s).
    Assigns risk scores for each URL rule relative to impact on suspicions.
    Accumulates number of hits for each rule from ALL URLs in the url_lists.
    Results show HOW MANY urls have hits.
    """
    cfg = (config or {}).get("rules", {}).get("url_redflags", {})
    total_score = 0.0
    details: List[str] = []
    url_list: List[str] = rec.urls
    url_display_pairs: List[tuple] = rec.url_display_pairs
    count_ip = 0
    count_at = 0
    count_subdomains = 0
    count_shortdomains = 0
    count_suskeyword = 0
    count_sustlds = 0

    # Early exit if rule is disabled or no URLs found
    if not cfg.get("enabled", True) or not url_list:
        return RuleHit("url_redflags", True, 0.0, Severity.LOW, {"reason": "rule disabled"})

    else:
        if url_list:
            for url in url_list:
                # Analyze features for each URL
                features: Dict = analyze_url_features(url, cfg)

                ip_present: bool = features["has_ip_address"]
                at_present: bool = features["has_at_symbol"]
                num_subdomains: int = features["num_subdomains"]
                has_shortened_domain: bool = features["has_shortened_domain"]
                sus_keyword_path: bool = features["suspicious_keyword_path"]
                suspicious_tlds: bool = features["suspicious_tlds"]

                # Rules are set below, to determine if URL is suspicious
                # Rules hit and aggregates the total hits for each URL rule
                if ip_present:
                    total_score += cfg.get("ip_url_penalty")  # 1.5 score
                    count_ip += 1

                if at_present:
                    total_score += cfg.get("at_symbol_penalty") # 1.5 score
                    count_at += 1

                if num_subdomains > 3:
                    total_score += cfg.get("subdomain_limit_penalty") # 2.0 score
                    count_subdomains += 1

                if has_shortened_domain:
                    total_score += cfg.get("shortener_penalty") # 1.2 score
                    count_shortdomains += 1

                if sus_keyword_path:
                    total_score += cfg.get("keyword_penalty") # 1.0 score
                    count_suskeyword += 1

                if suspicious_tlds:
                    total_score += cfg.get("suspicious_tld_penalty") # 1.0 score
                    count_sustlds += 1

            # Collect details for reporting
            details.append(f"ip_in_url: {count_ip}")
            details.append(f"at_symbol: {count_at}")
            details.append(f"url_>3_subdomains: {count_subdomains}")
            details.append(f"shortened_domain: {count_shortdomains}")
            details.append(f"suspicious_keyword: {count_suskeyword}")
            details.append(f"suspicious_tld: {count_sustlds}")

            # Determine if the rule passes based on total score
            passed = (total_score < 2.5)
            details = {"breakdown": " | ".join(details)} if details else {"hits": "none"}
            severity = Severity.LOW if total_score < 2.5 else Severity.MEDIUM

            return RuleHit("url_redflags", passed, total_score, severity, details)

        else:
            # No URLs found in record
            return RuleHit("url_redflags", True, total_score, Severity.LOW, {"hits": "no urls found"} )

        # Placeholder for future use of url_display_pairs
        if url_display_pairs:
            pass
        else:
            pass