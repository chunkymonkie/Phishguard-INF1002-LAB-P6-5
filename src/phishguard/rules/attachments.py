# rule: risky attachments

from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity


def rule_risky_attachments(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Detect risky attachment types (stub implementation)
    
    This is a placeholder implementation that returns a safe result.
    Full implementation would check for dangerous file extensions.
    """
    cfg = (config or {}).get("rules", {}).get("attachments", {})
    if not cfg.get("enabled", True):
        return RuleHit("attachments", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    # Placeholder - always pass for now
    return RuleHit("attachments", True, 0.0, Severity.LOW, {"status": "stub implementation"})