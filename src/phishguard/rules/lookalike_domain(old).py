from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity

try:
    import Levenshtein as lev
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False


def rule_lookalike_domain(rec: EmailRecord, config: Dict) -> RuleHit:
    """Simple lookalike domain detection"""
    config = (config or {}).get("rules", {}).get("lookalike_domain", {})
    
    # Skip if library not available
    if not LEVENSHTEIN_AVAILABLE:
        return RuleHit("lookalike_domain", True, 0.0, Severity.LOW, {"reason": "library not available"})
    
    # Extract sender domain
    if '@' not in rec.from_addr:
        return RuleHit("lookalike_domain", True, 0.0, Severity.LOW, {"reason": "invalid email format"})
    
    sender_domain = rec.from_addr.split('@')[-1].lower()
    
    # Common legitimate domains to check against
    legitimate_domains = config.get("protected_domains", [])
    
    # Check if sender domain is suspiciously similar to any legitimate domain
    for legit_domain in legitimate_domains:
        distance = lev.distance(legit_domain, sender_domain)
        
        # If distance is 1-3, it's suspicious (typosquatting)
        if 1 <= distance <= 3:
            return RuleHit(
                "lookalike_domain",
                False,  # Failed (suspicious)
                3.0,    # Fixed score for simplicity
                Severity.HIGH,
                {
                    "reason": f"'{sender_domain}' looks like '{legit_domain}' (typosquatting)",
                    "legitimate": legit_domain,
                    "suspicious": sender_domain,
                    "distance": distance
                }
            )
    
    # No suspicious matches
    return RuleHit("lookalike_domain", True, 0.0, Severity.LOW, {"reason": "domain looks safe"})