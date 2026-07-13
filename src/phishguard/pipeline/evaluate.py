from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from email.message import EmailMessage

from phishguard.schema import EmailRecord, RuleHit
from phishguard.ingestion.loaders import iterate_emails
from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body
from phishguard.features.extractors import extract_urls, extract_attachments
from phishguard.scoring.aggregate import RuleFunction, evaluate_email

#==========================================
#         Email Record Construction       =
#==========================================

def build_email_record(msg: EmailMessage) -> EmailRecord:
    """
    Constructs an EmailRecord object from an EmailMessage.
    Extracts and normalizes headers, addresses, body, URLs, and attachments.
    """
    header = normalize_header(msg)
    from_display, from_addr, reply_to_addr = decode_address(msg)
    body_text, body_html = extract_body(msg)
    urls, url_pairs = extract_urls(body_text, body_html)
    attachments = extract_attachments(msg)
    spf, dkim, dmarc = None, None, None  # Placeholder for actual SPF, DKIM, DMARC checks

    rec = EmailRecord(
        from_display=from_display,
        from_addr=from_addr,
        reply_to_addr=reply_to_addr,
        subject=header.get('subject', ''),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        url_display_pairs=url_pairs,
        attachments=attachments,
        headers=header,
        spf_pass=spf,
        dkim_pass=dkim,
        dmarc_pass=dmarc
    )

    return rec

#==========================================
#         Email Evaluation Pipeline       =
#==========================================

def evaluate_email_file(
    source: Path,
    rules: Iterable[RuleFunction],
    config: Dict
) -> List[Tuple[str, float, str, list[RuleHit]]]:
    """
    Pipeline for evaluating a single email file or a directory of email files.
    Builds email records for each email, runs the rules, and classifies them.
    Returns a list of tuples: [filename, score, classification, hits]
    """
    results: List[Tuple[str, float, str, list[RuleHit]]] = []
    for origin, msg in iterate_emails(source):
        rec = build_email_record(msg)
        hits, total_score, label = evaluate_email(rec, rules, config)
        results.append((str(origin), total_score, label, hits))
    return results

#==========================================
#      Email Evaluation (Dict Output)     =
#==========================================

def evaluate_email_file_dict(
    source: Path,
    rules: Iterable[RuleFunction],
    config: Dict
) -> List[Dict]:
    """
    Similar to evaluate_email_file, but returns results as a list of dictionaries
    with detailed information for each email, including rule hit details.
    """
    results: List[Dict] = []
    for origin, message in iterate_emails(source):
        rec = build_email_record(message)
        hits, total_score, label = evaluate_email(rec, rules, config)

        result = {
            "file_path": str(origin),
            "from_addr": rec.from_addr,
            "subject": rec.subject,
            "classification": label,
            "total_score": total_score,
            "rule_hits": [
                {
                    "rule_name": h.rule_name,
                    "passed": h.passed,
                    "score_delta": h.score_delta,
                    "severity": getattr(h.severity, "name", str(h.severity)),
                    "details": h.details,
                }
                for h in hits
            ],
        }
        results.append(result)
    return results
