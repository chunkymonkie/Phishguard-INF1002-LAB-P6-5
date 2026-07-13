from phishguard.normalize.parse_mime import normalize_header, extract_body, decode_address
from phishguard.ingestion.loaders import iterate_emails

# Iterate through all emails returned by iterate_emails
for origin, message in iterate_emails(r""):
    # Print the normalized header of the email message
    print(normalize_header(message))
    # Extract plain text and HTML body from the email message
    body_text, html_text = extract_body(message)
    # Print the first 100 characters of the plain text body
    print(f"Body Text: {body_text[:100]}...")  # Print first 100 characters of body text
    # If HTML body exists, print the first 100 characters
    if html_text:
        print(f"HTML Text: {html_text[:100]}...")  # Print first 100 characters of HTML text if available
    # Print the decoded email address from the message
    print(decode_address(message))