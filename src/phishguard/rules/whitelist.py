import re
from typing import List, Dict
import math
from phishguard.schema import RuleHit, Severity, EmailRecord  


## Helper function ##
def check_random_generated(sender_localpart: str) -> bool:
    """Detect if an email local-part looks random-generated."""
    if not sender_localpart:
        return False
    sender_localpart = sender_localpart.lower()

    if len(sender_localpart) < 4:
        return False

    # Calculates ratio of a feature in the local part
    digit_ratio = sum(char.isdigit() for char in sender_localpart) / len(sender_localpart)
    special_ratio = sum(not char.isalnum() for char in sender_localpart) / len(sender_localpart)
    vowel_ratio = sum(char in "aeiou" for char in sender_localpart) / len(sender_localpart)
    consonant_ratio = sum(char in "bcdfghjklmnpqrstvwxyz" for char in sender_localpart) / len(sender_localpart)

    freq = {char: sender_localpart.count(char) / len(sender_localpart) for char in set(sender_localpart)}
    entropy = -sum(probability * math.log2(probability) for probability in freq.values())

    # These variables contain boolean statements, depending on the ratio or features found
    no_vowels = vowel_ratio < 0.15
    many_consonants = consonant_ratio > 0.7
    consecutive_consonants = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", sender_localpart))
    alternating_underscore = bool(re.search(r"(?:[a-z]_){2,}", sender_localpart))
    repeating_chars = bool(re.search(r"([a-z0-9])\1{2,}", sender_localpart))

    # Aggregation of scoring after identifying all features of local part
    score = sum([
        digit_ratio > 0.3,
        special_ratio > 0.2,
        no_vowels,
        many_consonants,
        consecutive_consonants,
        alternating_underscore,
        repeating_chars,
        entropy > 3.5
    ])

    # Returns boolean statement, score >= 3 suggests a random-generated local part of email address returning True, otherwise False.
    return score >= 3


#==========================================
#           Whitelist Rule Logic          =
#==========================================

def rule_whitelist_and_analyse(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Check if SENDER'S email address:
    - Has domain name that matches whitelist (with optional subdomain check)
    - Has local part that looks random-generated
    - Contains suspicious keywords in local part
    - Contains suspicious keywords in domain name
    
    Returns RuleHit
    """
    details = {}
    score = 0.0
    passed = True
    emailaddr:str = rec.from_addr
    severity = Severity.LOW
    
    cfg = (config or {}).get("rules", {}).get("whitelist", {})
    whitelist_enabled: bool = cfg.get("enabled", True)
    subdomain_enabled: bool = cfg.get("include_subdomains", False)
    domain_whitelist: Dict[str, List] = cfg.get("domains", {})
    suspicious_words: List[str] = cfg.get("suspicious_email_addr", [])
    
    # Split the email into 2 parts, local part and sender_domain
    try:
        sender_localpart, sender_domain = emailaddr.lower().split("@")
    except:
        passed = False
        details = {"domain_whitelist": "email address format invalid"}
    
    # Validation of presence and format of sender's email address
    if not emailaddr or "@" not in emailaddr:
        passed = False
        details = {"domain_whitelist": "email address format invalid"}
    else:
        
        # If whitelist rule is enabled, Domain whitelist check
        if whitelist_enabled:
            domain_match = False
            
            # Loop through the domains in whitelist  (key=domains :value=[subdomains])
            # Check if domain is whitelisted first, then checks subdomain whitelist
            for whitelisted_domain in domain_whitelist.keys():
                # Extract only domain from sender's email address (exclude subdomain IF PRESENT)
                base_domain = re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1)
                
                # Extract subdomain separately, if subdomain check is enabled
                if subdomain_enabled:
                    if base_domain == whitelisted_domain:
                        # Subdomain extracted
                        subdomain = sender_domain.replace(whitelisted_domain, "").rstrip(".")
                        if subdomain in domain_whitelist[whitelisted_domain]:
                            domain_match = True
                            break
                        
                # No need for subdomain extraction if subdomain check is disabled
                else:
                    if sender_domain == whitelisted_domain or base_domain == whitelisted_domain:
                        domain_match = True
                        break
            
            # If match found, -0.5 score_delta and pass checks, else 0.0 and fail checks
            if domain_match:
                score += cfg.get("score_delta_on_match", -0.5)
                details["domain_whitelist"] = f"{emailaddr} matched whitelist"
            else:
                passed = False
                details["domain_whitelist"] = f"{emailaddr} not whitelisted"
                
        
        # If whitelist rule is disabled
        else:
            passed = False
            details["domain_whitelist"] = "rule disabled"
            
                
        #==========================================
        #          Email local-part checks        =
        #==========================================
        local_flags = []
        domain_flags = []
        penalty = cfg.get("emailaddr_penalty", 0.9) 

        # Calls function to check for random generation of local part
        if check_random_generated(sender_localpart):
            passed = False
            score += penalty
            local_flags.append("might be random generated")
            
        # Compares local part against predefined list in config.json 
        if any(word in sender_localpart for word in suspicious_words):
            passed = False
            score += penalty
            local_flags.append("contains suspicious keywords")
            
        # Compares domain part against predefined list in config.json 
        if any(word in sender_domain for word in suspicious_words):
            passed = False
            score += penalty
            domain_flags.append("domain contains suspicious keywords")

        # Adding details to RuleHit object if anomalies found
        details["local_part"] = (
            f"Local part '{sender_localpart}' {' and '.join(local_flags)}"
            if local_flags else f"Local part '{sender_localpart}' seems normal"
        )
        details["sender_domain"] = (
            f"Domain '{sender_domain}' {' and '.join(domain_flags)}"
            if domain_flags else f"Domain '{sender_domain}' seems normal"
        )

        # Score would be > 0 if any part of the email address is suspicious
        severity =  Severity.LOW if score <=0.0 else Severity.MEDIUM
        
    
    return RuleHit("whitelist_and_analysis", passed, score, severity, details)