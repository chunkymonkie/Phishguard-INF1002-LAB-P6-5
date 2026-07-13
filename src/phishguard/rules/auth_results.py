# rule: authentication results

from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity


def rule_auth_results(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Check email authentication results (SPF, DKIM, DMARC) (stub implementation)
    
    This is a placeholder implementation that returns a safe result.
    Full implementation would penalize failed authentication.
    """
    cfg = (config or {}).get("rules", {}).get("auth_results", {})
    if not cfg.get("enabled", True):
        return RuleHit("auth_results", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    # Placeholder - always pass for now
    return RuleHit("auth_results", True, 0.0, Severity.LOW, {"status": "stub implementation"})