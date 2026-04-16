import re
import logging

logger = logging.getLogger(__name__)

URGENCY_KEYWORDS = [
    "immediate action required",
    "urgent",
    "act now",
    "expires today",
    "final warning",
    "last chance",
    "limited time",
    "respond immediately",
    "time sensitive",
    "don't delay",
    "must respond",
    "within 24 hours",
    "within 48 hours",
    "account will be closed",
    "account will be suspended",
    "account will be terminated",
    "failure to respond",
    "unauthorized activity",
    "unusual activity",
    "suspicious activity detected",
    "security alert",
    "security warning",
    "action required immediately",
]

CREDENTIAL_PHRASES = [
    "verify your account",
    "confirm your identity",
    "update your information",
    "verify your identity",
    "enter your password",
    "confirm your password",
    "update your password",
    "reset your password",
    "login credentials",
    "sign in to verify",
    "re-enter your credentials",
    "validate your account",
    "provide your details",
    "submit your information",
    "enter your social security",
    "enter your ssn",
    "enter your credit card",
    "bank account details",
    "provide your bank",
    "verify payment information",
    "confirm payment details",
    "enter your pin",
    "security question answer",
    "mother's maiden name",
]

SUSPICIOUS_PATTERNS = [
    (r"dear\s+(customer|user|account\s*holder|valued\s+member|sir|madam)", "Generic salutation detected"),
    (r"click\s+(here|below|the\s+link)", "Clickbait language detected"),
    (r"congratulations.*?(won|winner|selected|chosen)", "Prize/lottery scam language"),
    (r"(million|thousand)\s+dollars", "Financial lure detected"),
    (r"wire\s+transfer", "Wire transfer request"),
    (r"western\s+union", "Western Union mention"),
    (r"bitcoin|cryptocurrency|crypto\s+wallet", "Cryptocurrency mention"),
    (r"(nigerian|foreign)\s+(prince|minister|official)", "Advance fee fraud language"),
    (r"inheritance.*?(claim|unclaimed)", "Inheritance scam language"),
    (r"invoice\s+attached|see\s+attached\s+invoice", "Suspicious invoice reference"),
    (r"your\s+account\s+(has\s+been|was)\s+(compromised|hacked|breached)", "Account compromise scare"),
    (r"we\s+(detected|noticed|found)\s+(unusual|suspicious|unauthorized)", "Fear-inducing alert language"),
    (r"(refund|reimbursement)\s+(pending|available|ready)", "Fake refund language"),
    (r"irs|internal\s+revenue", "Tax authority impersonation"),
    (r"helpdesk|help\s+desk|it\s+department|tech\s+support", "IT support impersonation"),
]

THREAT_PHRASES = [
    "your account has been compromised",
    "we have detected unauthorized access",
    "your account is at risk",
    "legal action will be taken",
    "failure to comply",
    "law enforcement",
    "arrest warrant",
    "court order",
    "cease and desist",
    "account termination notice",
]


def analyze_rules(subject: str, body: str) -> list[dict]:
    """
    Analyze email content against rule-based detection patterns.
    Returns a list of flagged rules with descriptions and severity.
    """
    flags = []
    combined_text = f"{subject} {body}".lower()

    for keyword in URGENCY_KEYWORDS:
        if keyword.lower() in combined_text:
            flags.append({
                "rule": "urgency_keyword",
                "keyword": keyword,
                "description": f"Urgency keyword detected: '{keyword}'",
                "severity": "high"
            })

    for phrase in CREDENTIAL_PHRASES:
        if phrase.lower() in combined_text:
            flags.append({
                "rule": "credential_request",
                "keyword": phrase,
                "description": f"Credential harvesting phrase: '{phrase}'",
                "severity": "critical"
            })

    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            flags.append({
                "rule": "suspicious_pattern",
                "pattern": pattern,
                "description": description,
                "severity": "medium"
            })

    for phrase in THREAT_PHRASES:
        if phrase.lower() in combined_text:
            flags.append({
                "rule": "threat_language",
                "keyword": phrase,
                "description": f"Threatening/coercive language: '{phrase}'",
                "severity": "high"
            })

    exclamation_count = combined_text.count("!")
    if exclamation_count >= 3:
        flags.append({
            "rule": "excessive_punctuation",
            "description": f"Excessive exclamation marks ({exclamation_count} found)",
            "severity": "low"
        })

    caps_words = re.findall(r'\b[A-Z]{4,}\b', f"{subject} {body}")
    if len(caps_words) >= 3:
        flags.append({
            "rule": "excessive_caps",
            "description": f"Excessive capitalization ({len(caps_words)} all-caps words)",
            "severity": "low"
        })

    seen = set()
    deduped = []
    for flag in flags:
        key = flag["description"]
        if key not in seen:
            seen.add(key)
            deduped.append(flag)

    logger.info(f"Rule engine detected {len(deduped)} flags")
    return deduped
