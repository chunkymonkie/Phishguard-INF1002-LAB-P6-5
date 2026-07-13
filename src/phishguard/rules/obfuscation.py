# rule: obfuscation detection

from typing import Dict
from phishguard.schema import EmailRecord, RuleHit, Severity


def rule_obfuscation(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Detect text obfuscation techniques (stub implementation)
    
    This is a placeholder implementation that returns a safe result.
    Full implementation would check for zero-width chars, homoglyphs, etc.
    """
    cfg = (config or {}).get("rules", {}).get("obfuscation", {})
    if not cfg.get("enabled", True):
        return RuleHit("obfuscation", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    # Placeholder - always pass for now
    return RuleHit("obfuscation", True, 0.0, Severity.LOW, {"status": "stub implementation"})