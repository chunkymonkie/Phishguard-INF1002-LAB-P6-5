# Import individual rule functions from their respective modules
from .whitelist import rule_whitelist_and_analyse
from .headers import rule_headers_analyse
from .url_redflags import rule_urlredflags
from .keywords import rule_keywords
from .lookalike_domain import rule_lookalike_domain
from .attachments import rule_risky_attachments

# List of all rule functions to be applied by the phishguard system
RULES = [
    rule_headers_analyse,                      # Detects anomalies in headers of emails
    rule_whitelist_and_analyse,                # Checks if the domain is whitelisted (additional detection on email address anomalies)
    rule_urlredflags,                          # Detects suspicious URL patterns
    rule_keywords,                             # Searches for phishing-related keywords
    rule_lookalike_domain,                     # Identifies lookalike domains
    rule_risky_attachments,                    # Flags risky file attachments
]
