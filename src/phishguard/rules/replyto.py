# rule: reply-to mismatch

from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity


def rule_reply_to_mismatch(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Detect Reply-To header mismatches (stub implementation)
    
    This is a placeholder implementation that returns a safe result.
    Full implementation would check if Reply-To differs from From address.
    """
    cfg = (config or {}).get("rules", {}).get("reply_to_mismatch", {})
    if not cfg.get("enabled", True):
        return RuleHit("reply_to_mismatch", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    # Placeholder - always pass for now
    return RuleHit("reply_to_mismatch", True, 0.0, Severity.LOW, {"status": "stub implementation"})