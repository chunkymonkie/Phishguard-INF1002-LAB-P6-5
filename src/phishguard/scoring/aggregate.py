from __future__ import annotations

from typing import Dict, List, Tuple, Callable, Iterable
from phishguard.schema import EmailRecord, RuleHit, Severity

#==========================================
#           Type Definitions              =
#==========================================

# Each rule is a function that takes (EmailRecord, config) and returns RuleHit
RuleFunction = Callable[[EmailRecord, Dict], RuleHit]

#==========================================
#           Rule Execution                =
#==========================================

def run_rules(rec: EmailRecord, rules: Iterable[RuleFunction], config: Dict) -> List[RuleHit]:
    """
    Execute all rules in the given order and collect their results.

    Args:
        rec (EmailRecord): The email record to evaluate.
        rules (Iterable[RuleFunction]): List of rule functions to apply.
        config (Dict): Configuration dictionary for rules.

    Returns:
        List[RuleHit]: List of RuleHit objects from each rule.
    """
    hits: List[RuleHit] = []
    for rule in rules:
        hit = rule(rec, config)
        hits.append(hit)
    return hits

#==========================================
#           Score Aggregation             =
#==========================================

def aggregate(hits: List[RuleHit], config: Dict) -> Tuple[float, str]:
    """
    Sum up scores from all rule hits and classify email based on thresholds.

    Args:
        hits (List[RuleHit]): List of RuleHit objects.
        config (Dict): Configuration dictionary, may contain thresholds.

    Returns:
        Tuple[float, str]: Total score and classification label.
    """
    thresholds = config.get('thresholds', {})
    if not thresholds:
        thresholds = {"safe_max": 2.0, "phishing_min": 2.0}
    
    # Only count score_delta for rules that did not pass
    total_score = sum(hit.score_delta for hit in hits if hit.passed is False)
    if total_score < thresholds.get("safe_max", 2.0):
        label = "Safe"
    elif total_score >= thresholds.get("phishing_min", 2.0):
        label = "Phishing"
    else:
        label = "Unknown"
    return total_score, label

#==========================================
#           Email Evaluation              =
#==========================================

def evaluate_email(rec: EmailRecord, rules: Iterable[RuleFunction], config: Dict) -> Tuple[List[RuleHit], float, str]:
    """
    Run rules on an email record, sum the scores, and classify the email.

    Args:
        rec (EmailRecord): The email record to evaluate.
        rules (Iterable[RuleFunction]): List of rule functions to apply.
        config (Dict): Configuration dictionary for rules and thresholds.

    Returns:
        Tuple[List[RuleHit], float, str]: (list of RuleHits, total score, classification label)
    """
    hit = run_rules(rec, rules, config)
    total_score, label = aggregate(hit, config)
    return hit, total_score, label