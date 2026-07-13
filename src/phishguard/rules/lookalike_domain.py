from typing import Dict, List, Tuple
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.rules.utils import (
    to_ascii_domain,
    top_level_domain,
    parse_email_domain,
    parse_url_host,
    registrable_domain,
    apply_lookalike_variants,
    levenshtein_distance)

def _check_homograph_attack(candidate: str, protected: str, confusables: List[str]) -> float:
    """
    Check if candidate domain uses confusable characters to mimic protected domain.
    Returns a score > 0 if homograph attack detected, 0 otherwise.
    """
    if not candidate or not protected or len(candidate) != len(protected):
        return 0.0
    
    # Create mapping of confusable characters
    confusable_map = {}
    for pair in confusables:
        if ':' in pair:
            left, right = pair.split(":", 1)
            left, right = left.strip(), right.strip()
            if left and right:
                # Map both directions for detection
                confusable_map[right.lower()] = left.lower()
                confusable_map[right.upper()] = left.lower()
    
    # Check character by character
    confusable_count = 0
    total_chars = len(candidate)
    
    for i, (c_char, p_char) in enumerate(zip(candidate.lower(), protected.lower())):
        if c_char != p_char:
            # Check if this is a confusable substitution
            if c_char in confusable_map and confusable_map[c_char] == p_char:
                confusable_count += 1
            elif c_char.upper() in confusable_map and confusable_map[c_char.upper()] == p_char:
                confusable_count += 1
            else:
                # Non-confusable difference, not a homograph attack
                return 0.0
    
    # If we found confusable substitutions and rest matches, it's an attack
    if confusable_count > 0:
        # Score based on how many confusable chars were used
        return 2.0 + (confusable_count * 0.5)
    
    return 0.0

def rule_lookalike_domain(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Detect brand impersonation via domain look-alikes.
    Compares:
      - From: domain (registrable)
      - (Optionally) URL hosts from the email body
    against a protected list using confusable normalization + edit distance.

    Config keys (with reasonable defaults if missing):
      protected_domains: List[str]
      max_edit_distance: int (1 or 2)
      score_distance_1: float
      score_distance_2: float
      tld_swap_penalty: float
      homograph_confusables: List[str] like ["l:I","rn:m","0:o","1:l","5:s"]
      etld_exceptions: List[str] like ["co.uk","com.au","com.sg","gov.sg"]   (optional)
      include_urls: bool (default True) — whether to also scan URL hosts
    """
    cfg = (config or {}).get("rules", {}).get("lookalike_domain", {})
    prot: List[str] = list((cfg.get("protected_domains") or []))
    max_d: int = int(cfg.get("max_edit_distance", 1))
    score_d1: float = float(cfg.get("score_distance_1", 2.5))
    score_d2: float = float(cfg.get("score_distance_2", 3.5))
    tld_pen: float = float(cfg.get("tld_swap_penalty", 1.0))
    confusables: List[str] = list((cfg.get("homograph_confusables") or []))
    etld_ex: List[str] = list((cfg.get("etld_exceptions") or ["co.uk", "com.au", "com.sg", "gov.sg"]))
    include_urls: bool = bool(cfg.get("include_urls", True))

    # Build candidate domains to evaluate from the email
    candidates: List[Tuple[str, str]] = []  # (kind, registrable_domain)

    # 1) From: sender domain
    sender_host = parse_email_domain(rec.from_addr)
    sender_host = to_ascii_domain(sender_host)
    sender_reg = registrable_domain(sender_host, effective_tld=etld_ex)
    if sender_reg:
        candidates.append(("from_addr", sender_reg))

    # 2) URL hosts in body (optional)
    if include_urls:
        seen_hosts = set()
        for url in rec.urls or []:
            host = parse_url_host(url)
            if not host:
                continue
            host = to_ascii_domain(host)
            reg = registrable_domain(host, effective_tld=etld_ex)
            if reg and reg not in seen_hosts:
                candidates.append(("url", reg))
                seen_hosts.add(reg)

    # Normalize protected list to registrable & confusable-canonical
    norm_protected: List[str] = []
    prot_regs: List[str] = []
    for d in prot:
        d_ascii = to_ascii_domain(d)
        reg = registrable_domain(d_ascii, effective_tld=etld_ex)
        prot_regs.append(reg)
        norm_protected.append(apply_lookalike_variants(reg, confusables))

    best_score = 0.0
    best_severity = Severity.LOW
    best_details: Dict[str, str] = {}
    hit_any = False

    for kind, cand in candidates:
        # First check for homograph attacks before normalization
        for prot_reg in prot_regs:
            # Check if this looks like a homograph attack
            homograph_score = _check_homograph_attack(cand, prot_reg, confusables)
            if homograph_score > 0:
                if homograph_score > best_score:
                    best_score = homograph_score
                    best_severity = Severity.HIGH
                    best_details = {
                        "kind": kind,
                        "candidate": cand,
                        "protected": prot_reg,
                        "distance": "homograph",
                        "note": "homograph_attack",
                    }
                    hit_any = True

        # Confusable-canonical for comparison
        cand_norm = apply_lookalike_variants(cand, confusables)

        # Check exact same SLD but different TLD (tld swap)
        # sld = second-level label (registrable minus the tld)
        c_parts = list(p for p in cand_norm.strip().rstrip(".").split(".") if p)
        if len(c_parts) >= 2:
            c_sld = c_parts[-2]
            c_tld = c_parts[-1]
        else:
            c_sld, c_tld = "", top_level_domain(cand_norm)

        # Evaluate distance against all protected
        for prot_reg, prot_norm in zip(prot_regs, norm_protected):
            # TLD swap: same SLD but different TLD
            p_parts = list(p for p in prot_norm.strip().rstrip(".").split(".") if p)
            p_sld = p_parts[-2] if len(p_parts) >= 2 else ""
            p_tld = p_parts[-1] if p_parts else ""

            # If SLD equal but TLD differs, consider a small penalty (TLD swap)
            tld_swap = (c_sld and p_sld and c_sld == p_sld and c_tld and p_tld and c_tld != p_tld)

            d = levenshtein_distance(cand_norm, prot_norm)

            score = 0.0
            severity = Severity.LOW
            note = ""

            if d == 0:
                # Exact registrable match → trusted/neutral (score stays 0)
                # (Whitelist rule typically handles this as a bonus.)
                note = "exact_match"
            elif d == 1 and max_d >= 1:
                score = max(score, score_d1)
                severity = Severity.HIGH
                note = "distance_1"
            elif d == 2 and max_d >= 2:
                score = max(score, score_d2)
                severity = Severity.CRITICAL
                note = "distance_2"

            if tld_swap:
                # Additive penalty for TLD swap (unless exact match already handled)
                score = max(score, tld_pen) if score == 0.0 else (score + tld_pen)
                if severity.value < Severity.MEDIUM.value:
                    severity = Severity.MEDIUM
                if note:
                    note += "+tld_swap"
                else:
                    note = "tld_swap"

            if score > best_score:
                best_score = score
                best_severity = severity
                best_details = {
                    "kind": kind,
                    "candidate": cand,
                    "protected": prot_reg,
                    "distance": str(d),
                    "note": note,
                }
                hit_any = True

    # Construct RuleHit
    if not hit_any or best_score <= 0.0:
        return RuleHit(
            rule_name="lookalike_domain",
            passed=True,
            score_delta=0.0,
            severity=Severity.LOW,
            details={"reason": "no_lookalike_detected"}
        )

    return RuleHit(
        rule_name="lookalike_domain",
        passed=False,
        score_delta=best_score,
        severity=best_severity,
        details=best_details
    )