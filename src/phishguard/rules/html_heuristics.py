# rule: HTML heuristics

from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity


def rule_html_heuristics(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Analyze HTML content for suspicious patterns (stub implementation)
    
    This is a placeholder implementation that returns a safe result.
    Full implementation would check for hidden text, forms, etc.
    """
    cfg = (config or {}).get("rules", {}).get("html_heuristics", {})
    if not cfg.get("enabled", True):
        return RuleHit("html_heuristics", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    # Placeholder - always pass for now
    return RuleHit("html_heuristics", True, 0.0, Severity.LOW, {"status": "stub implementation"})