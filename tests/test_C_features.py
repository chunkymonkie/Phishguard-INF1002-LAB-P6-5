# Import necessary modules and functions from the phishguard package
from phishguard.ingestion.loaders import iterate_emails
from phishguard.normalize.parse_mime import normalize_header, extract_body, decode_address
from phishguard.features.extractors import extract_urls, extract_attachments
from phishguard.schema.classes import EmailRecord

record = []  # List to store processed EmailRecord objects

# Iterate through emails using the iterate_emails function
for origin, message in iterate_emails(r""):
    # Normalize and extract header information
    header = normalize_header(message)
    # Decode sender and reply-to addresses
    from_display, from_addr, reply_to_addr = decode_address(message)
    # Extract plain text and HTML body from the email
    body_text, body_html = extract_body(message)
    # Extract URLs and their display pairs from the email body
    urls, url_pairs = extract_urls(body_text, body_html)
    # Extract attachments from the email
    attachments = extract_attachments(message)
    # Placeholder values for SPF, DKIM, and DMARC checks (to be implemented)
    spf, dkim, dmarc = None, None, None

    # Create an EmailRecord object with all extracted features
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

    # Append the EmailRecord to the list
    record.append(rec)

# Print the list of processed EmailRecord objects
print(record)