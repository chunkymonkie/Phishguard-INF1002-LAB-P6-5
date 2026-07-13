"""
Email scoring and rule aggregation module

This module coordinates the execution of all detection rules and aggregates
their results into a final risk score and classification.
"""

from typing import Dict, List, Tuple, Any
from phishguard.schema import EmailRecord, RuleHit, Severity


def evaluate_email(email_record: EmailRecord, config: Dict[str, Any]) -> Tuple[float, List[RuleHit]]:
    """
    Evaluate an email using all configured rules
    
    Args:
        email_record: Email data to analyze
        config: Configuration dictionary with rule settings
        
    Returns:
        Tuple of (total_score, list_of_rule_hits)
    """
    rule_hits = run_rules(email_record, config)
    total_score = aggregate(rule_hits)
    return total_score, rule_hits


def run_rules(email_record: EmailRecord, config: Dict[str, Any]) -> List[RuleHit]:
    """
    Execute all enabled rules against the email record
    
    Args:
        email_record: Email data to analyze
        config: Configuration with rule settings
        
    Returns:
        List of RuleHit objects from all executed rules
    """
    rule_hits = []
    
    # Import rule functions
    from phishguard.rules.whitelist import check_domain_whitelist
    from phishguard.rules.keywords import rule_keywords
    from phishguard.rules.url_redflags import detect_urlredflags
    from phishguard.rules.lookalike_domain import rule_lookalike_domain
    from phishguard.rules.replyto import rule_reply_to_mismatch
    from phishguard.rules.display_impersonation import rule_display_name_impersonation
    from phishguard.rules.attachments import rule_risky_attachments
    from phishguard.rules.auth_results import rule_auth_results
    from phishguard.rules.html_heuristics import rule_html_heuristics
    from phishguard.rules.obfuscation import rule_obfuscation
    
    # Execute each rule if enabled
    rule_functions = [
        ('whitelist', check_domain_whitelist),
        ('keywords', rule_keywords),
        ('url_redflags', detect_urlredflags),
        ('lookalike_domain', rule_lookalike_domain),
        ('reply_to_mismatch', rule_reply_to_mismatch),
        ('display_name_impersonation', rule_display_name_impersonation),
        ('attachments', rule_risky_attachments),
        ('auth_results', rule_auth_results),
        ('html_heuristics', rule_html_heuristics),
        ('obfuscation', rule_obfuscation)
    ]
    
    for rule_name, rule_function in rule_functions:
        try:
            # Check if rule is enabled in config
            rule_config = config.get('rules', {}).get(rule_name, {})
            if rule_config.get('enabled', True):
                # Execute rule
                if rule_name == 'whitelist':
                    hit = rule_function(email_record)
                else:
                    hit = rule_function(email_record, config)
                
                if hit:
                    rule_hits.append(hit)
        except Exception as e:
            # Create error hit for failed rules
            error_hit = RuleHit(
                rule_name=rule_name,
                passed=True,  # Don't penalize for rule errors
                score_delta=0.0,
                severity=Severity.LOW,
                details={'error': f'Rule execution failed: {str(e)}'}
            )
            rule_hits.append(error_hit)
            print(f"Warning: Rule {rule_name} failed: {e}")
    
    return rule_hits


def aggregate(rule_hits: List[RuleHit]) -> float:
    """
    Aggregate rule hit scores into a total risk score
    
    Args:
        rule_hits: List of RuleHit objects from executed rules
        
    Returns:
        Total aggregated score
    """
    total_score = 0.0
    
    for hit in rule_hits:
        if not hit.passed:  # Only add score if rule detected something suspicious
            total_score += hit.score_delta
    
    # Ensure score is non-negative
    return max(0.0, total_score)


# Additional helper functions for compatibility
def calculate_score(rule_hits: List[RuleHit]) -> float:
    """Sum up the score from each rule (for backward compatibility)"""
    return sum(hit.score_delta for hit in rule_hits if not hit.passed)


def classify_email(score: float, thresholds: dict) -> str:
    """
    Classify email based on score and thresholds
    
    Thresholds example:
    {
        "safe": 0,
        "suspicious": 5,
        "phishing": 15
    }
    """
    if score < thresholds.get("suspicious", 2.0):
        return "Safe"
    elif score < thresholds.get("phishing", 2.0):
        return "Suspicious"
    else:
        return "Phishing"
