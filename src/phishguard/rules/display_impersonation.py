# rule: display name impersonation

from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity


def rule_display_name_impersonation(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Detect display name impersonation (stub implementation)
    
    This is a placeholder implementation that returns a safe result.
    Full implementation would check for impersonation of known brands/people.
    """
    cfg = (config or {}).get("rules", {}).get("display_name_impersonation", {})
    if not cfg.get("enabled", True):
        return RuleHit("display_name_impersonation", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    # Placeholder - always pass for now
    return RuleHit("display_name_impersonation", True, 0.0, Severity.LOW, {"status": "stub implementation"})