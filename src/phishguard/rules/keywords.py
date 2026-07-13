from __future__ import annotations

import re
from typing import Dict, List, Tuple
from phishguard.schema import EmailRecord, RuleHit, Severity

#==========================================
#           Regex Pattern Helpers         =
#==========================================

def _compile_pattern(phrase: str, ci: bool, word_boundaries: bool) -> re.Pattern:
    """
    Build a regex pattern from a keyword.
    If word_boundaries is True, the pattern will match whole words only.
    If Case Insensitive (ci) is True, the pattern will be case insensitive.
    """
    core_pattern = re.escape(phrase)
    if word_boundaries:
        pattern = r'\b' + core_pattern + r'\b'
    else:
        pattern = core_pattern
    flags = re.IGNORECASE if ci else 0
    return re.compile(pattern, flags)

def _count_occurrence(text: str, pattern: re.Pattern) -> int:
    """
    Count occurrences of a pattern in a text.
    """
    if not text:
        return 0
    # More memory efficient than len(pattern.findall(text))
    return sum(1 for _ in pattern.finditer(text))

#==========================================
#      Occurrence Allocation & Scoring    =
#==========================================

def _allocate_with_cap(segment_counts: List[Tuple[str, int, float]], per_phrase_max: int) -> Tuple[float, List[Tuple[str, int]]]:
    """
    Allocate occurrences to segments, favoring higher positions first (subject > intro > body).
    Returns (effective_weighted_occurrence, [(segment, count), ...])
    """
    # Sort by weight in descending order
    ordered = sorted(segment_counts, key=lambda x: x[2], reverse=True)
    remaining = per_phrase_max
    effective_weighted_occurrence = 0.0
    used_count: List[Tuple[str, int]] = []
    for segment, count, boost in ordered:
        if remaining <= 0 or count <= 0:
            used_count.append((segment, 0))
            continue
        alloc = min(count, remaining)
        effective_weighted_occurrence += alloc * boost
        used_count.append((segment, alloc))
        remaining -= alloc
    # Retain original order for reporting
    seg_to_count = {seg: cnt for seg, cnt in used_count}
    original_used_count = [(seg, seg_to_count[seg]) for seg, _, _ in segment_counts]
    return effective_weighted_occurrence, original_used_count

#==========================================
#           Main Rule: Keywords           =
#==========================================

def rule_keywords(rec: EmailRecord, config: Dict) -> RuleHit:
    """
    Detects keywords in email fields (subject, intro and body) and returns score based on occurrence, 
    weight and position in the email. Higher weight is given to keywords found in Subject and Intro 
    (first 200 characters). The scores are also capped by per_phrase_max and max_total.
    """
    #-------------------------------
    #   Load Configuration Values
    #-------------------------------
    cfg = (config or {}).get("rules", {}).get("keywords", {})
    if not cfg.get("enabled", True):
        return RuleHit("keywords", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    ci = cfg.get("case_insensitive", True)
    weights: Dict[str, float] = cfg.get("weights", {})
    max_total: float = cfg.get("max_total", 2.0)

    count_cfg = cfg.get("count", {})
    per_phrase_max: int = count_cfg.get("per_phrase_max", 2)
    word_boundaries: bool = count_cfg.get("word_boundaries", True)

    pos_cfg = cfg.get("position", {})
    subject_boost: float = pos_cfg.get("subject", 1.5)
    intro_char: int = pos_cfg.get("intro_chars", 200)
    intro_boost: float = pos_cfg.get("intro", 1.25)
    body_boost: float = pos_cfg.get("body", 1.0)
    all_caps_boost: float = pos_cfg.get("allcaps_subject_penalty", 0.2)

    subject = rec.subject or ""
    body = rec.body_text or ""

    total_score = 0.0
    details: List[str] = []

    #-------------------------------
    #   Subject All Caps Penalty
    #-------------------------------
    # Apply penalty if subject is fully capitalized
    if all_caps_boost and subject and subject.upper() == subject:
        total_score += all_caps_boost
        details.append(f"Subject all caps(+{all_caps_boost})")

    #-------------------------------
    #   Keyword Detection & Scoring
    #-------------------------------
    for phrase, weight in weights.items():
        if not phrase or weight <= 0.0:
            continue
        weight = float(weight)
        pattern = _compile_pattern(phrase, ci, word_boundaries=word_boundaries)

        # Count occurrences per segment (Subject, Intro, Body)
        c_subject = _count_occurrence(subject, pattern)
        c_intro = 0
        c_body = 0

        # Split intro/body by character position in body
        for match in pattern.finditer(body):
            if match.start() < intro_char:
                c_intro += 1
            else:
                c_body += 1
    
        if c_subject == 0 and c_intro == 0 and c_body == 0:
            continue

        # Allocate occurrences up till per_phrase_max, favoring higher weighted segments first
        effective_weighted_occurrence, used_count = _allocate_with_cap(
            segment_counts=[
                ("subject", c_subject, subject_boost),
                ("intro", c_intro, intro_boost), 
                ("body", c_body, body_boost)
            ],
            per_phrase_max=per_phrase_max
        )

        phrase_score = effective_weighted_occurrence * weight
        if phrase_score > 0.0:
            total_score += phrase_score
            used_mapping = {name: count for name, count in used_count}
            details.append(
                f"{phrase} subj:{used_mapping['subject']} intro:{used_mapping['intro']} body:{used_mapping['body']} => +{phrase_score:.2f}"
            )
            # Early exit if max_total reached
            if total_score >= max_total:
                total_score = max_total
                break
    
    #-------------------------------
    #   Severity & Result Assembly
    #-------------------------------
    severity = Severity.LOW if total_score < 1.0 else Severity.MEDIUM
    passed = (total_score == 0.0)
    details = {"breakdown": " | ".join(details)} if details else {"hits": "none"}
    return RuleHit("keywords", passed, total_score, severity, details)
