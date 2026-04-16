import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def analyze_headers(
    sender: str,
    reply_to: str,
    return_path: str,
    received_chain: list[str],
    headers: dict[str, str],
    authentication_results: str,
    dkim_signature: str,
    message_id: str,
    x_mailer: str,
) -> list[dict]:
    """
    Perform forensic analysis on email headers.
    Returns a list of detected header anomalies.
    """
    issues = []

    reply_to_issues = _check_reply_to_mismatch(sender, reply_to)
    if reply_to_issues:
        issues.extend(reply_to_issues)

    return_path_issues = _check_return_path_mismatch(sender, return_path)
    if return_path_issues:
        issues.extend(return_path_issues)

    spoof_issues = _detect_sender_spoofing(sender, received_chain, headers)
    if spoof_issues:
        issues.extend(spoof_issues)

    auth_issues = _check_authentication(authentication_results, dkim_signature)
    if auth_issues:
        issues.extend(auth_issues)

    chain_issues = _analyze_received_chain(received_chain)
    if chain_issues:
        issues.extend(chain_issues)

    header_issues = _check_suspicious_headers(headers, x_mailer, message_id)
    if header_issues:
        issues.extend(header_issues)

    logger.info(f"Header analyzer found {len(issues)} issues")
    return issues


def _extract_domain(email_addr: str) -> str:
    """Extract domain from an email address."""
    match = re.search(r'@([\w.-]+)', email_addr)
    return match.group(1).lower() if match else ""


def _extract_email(addr_string: str) -> str:
    """Extract the email address from a header value like 'Name <email@domain.com>'."""
    match = re.search(r'<([^>]+)>', addr_string)
    if match:
        return match.group(1).lower()
    match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', addr_string)
    if match:
        return match.group(0).lower()
    return addr_string.strip().lower()


def _check_reply_to_mismatch(sender: str, reply_to: str) -> list[dict]:
    """Detect mismatch between From and Reply-To addresses."""
    issues = []

    if not reply_to or reply_to == "None" or reply_to.strip() == "":
        return issues

    sender_email = _extract_email(sender)
    reply_to_email = _extract_email(reply_to)

    if not sender_email or not reply_to_email:
        return issues

    if sender_email != reply_to_email:
        sender_domain = _extract_domain(sender_email)
        reply_domain = _extract_domain(reply_to_email)

        severity = "critical" if sender_domain != reply_domain else "high"

        issues.append({
            "issue": "reply_to_mismatch",
            "description": (
                f"Reply-To address ({reply_to_email}) differs from sender ({sender_email}). "
                f"Replies will go to a different {'domain' if sender_domain != reply_domain else 'address'}."
            ),
            "severity": severity,
            "from": sender_email,
            "reply_to": reply_to_email,
        })

    return issues


def _check_return_path_mismatch(sender: str, return_path: str) -> list[dict]:
    """Detect mismatch between From and Return-Path."""
    issues = []

    if not return_path or return_path == "None" or return_path.strip() == "":
        return issues

    sender_domain = _extract_domain(sender)
    return_path_domain = _extract_domain(return_path)

    if not sender_domain or not return_path_domain:
        return issues

    if sender_domain != return_path_domain:
        issues.append({
            "issue": "return_path_mismatch",
            "description": (
                f"Return-Path domain ({return_path_domain}) does not match "
                f"sender domain ({sender_domain}). Possible spoofing."
            ),
            "severity": "high",
            "sender_domain": sender_domain,
            "return_path_domain": return_path_domain,
        })

    return issues


def _detect_sender_spoofing(sender: str, received_chain: list[str], headers: dict[str, str]) -> list[dict]:
    """Detect potential sender spoofing via header analysis."""
    issues = []

    sender_domain = _extract_domain(sender)
    if not sender_domain:
        return issues

    free_email_providers = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "mail.com", "protonmail.com", "icloud.com",
    ]

    display_name = ""
    match = re.match(r'^"?([^"<]+)"?\s*<', sender)
    if match:
        display_name = match.group(1).strip().lower()

    business_keywords = ["bank", "paypal", "amazon", "apple", "microsoft", "support", "admin", "security"]
    if display_name and sender_domain in free_email_providers:
        for keyword in business_keywords:
            if keyword in display_name:
                issues.append({
                    "issue": "display_name_spoofing",
                    "description": (
                        f"Sender claims to be '{display_name}' but uses free email "
                        f"provider ({sender_domain}). Likely impersonation."
                    ),
                    "severity": "critical",
                })
                break

    if received_chain:
        first_hop = received_chain[-1] if received_chain else ""
        first_hop_lower = first_hop.lower()

        if sender_domain and sender_domain not in first_hop_lower:
            origin_match = re.search(r'from\s+([\w.-]+)', first_hop_lower)
            if origin_match:
                origin_domain = origin_match.group(1)
                if origin_domain != sender_domain and not origin_domain.endswith("." + sender_domain):
                    issues.append({
                        "issue": "origin_domain_mismatch",
                        "description": (
                            f"Email origin ({origin_domain}) does not match "
                            f"sender domain ({sender_domain}). Possible relay abuse or spoofing."
                        ),
                        "severity": "high",
                    })

    return issues


def _check_authentication(authentication_results: str, dkim_signature: str) -> list[dict]:
    """Simulate SPF/DKIM anomaly detection based on header values."""
    issues = []

    if authentication_results and authentication_results != "None":
        auth_lower = authentication_results.lower()

        if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
            issues.append({
                "issue": "spf_failure",
                "description": "SPF authentication failed. Email may not be from the claimed sender domain.",
                "severity": "critical",
            })
        elif "spf=none" in auth_lower:
            issues.append({
                "issue": "spf_missing",
                "description": "No SPF record found for sender domain. Cannot verify sender authenticity.",
                "severity": "medium",
            })

        if "dkim=fail" in auth_lower:
            issues.append({
                "issue": "dkim_failure",
                "description": "DKIM signature verification failed. Email integrity cannot be confirmed.",
                "severity": "critical",
            })
        elif "dkim=none" in auth_lower:
            issues.append({
                "issue": "dkim_missing",
                "description": "No DKIM signature present. Email authenticity cannot be verified.",
                "severity": "medium",
            })

        if "dmarc=fail" in auth_lower:
            issues.append({
                "issue": "dmarc_failure",
                "description": "DMARC policy check failed. High likelihood of domain spoofing.",
                "severity": "critical",
            })

    else:
        if not dkim_signature or dkim_signature == "None":
            issues.append({
                "issue": "no_authentication_headers",
                "description": "No email authentication headers (SPF/DKIM/DMARC) found. Cannot verify sender.",
                "severity": "medium",
            })

    return issues


def _analyze_received_chain(received_chain: list[str]) -> list[dict]:
    """Analyze the Received header chain for anomalies."""
    issues = []

    if len(received_chain) > 10:
        issues.append({
            "issue": "long_received_chain",
            "description": (
                f"Unusually long Received header chain ({len(received_chain)} hops). "
                f"May indicate relay abuse or routing obfuscation."
            ),
            "severity": "medium",
        })

    for i, hop in enumerate(received_chain):
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hop):
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', hop)
            if ip_match:
                ip = ip_match.group(1)
                octets = ip.split(".")
                if octets[0] in ("10",) or (octets[0] == "172" and 16 <= int(octets[1]) <= 31) or (octets[0] == "192" and octets[1] == "168"):
                    continue

    return issues


def _check_suspicious_headers(headers: dict[str, str], x_mailer: str, message_id: str) -> list[dict]:
    """Check for suspicious header patterns."""
    issues = []

    if x_mailer and x_mailer != "None":
        suspicious_mailers = ["PHPMailer", "SwiftMailer", "The Bat!", "Mass Mailer"]
        for mailer in suspicious_mailers:
            if mailer.lower() in x_mailer.lower():
                issues.append({
                    "issue": "suspicious_mailer",
                    "description": f"Email sent using potentially suspicious mail client: {x_mailer}",
                    "severity": "medium",
                })
                break

    if message_id and message_id != "None":
        if not re.match(r'^<[^>]+>$', message_id.strip()):
            if "@" not in message_id:
                issues.append({
                    "issue": "malformed_message_id",
                    "description": "Message-ID header is malformed. May indicate automated/spoofed email.",
                    "severity": "low",
                })

    if "X-Priority" in headers:
        priority = headers["X-Priority"].strip()
        if priority in ("1", "2"):
            issues.append({
                "issue": "high_priority_flag",
                "description": "Email marked as high priority. Often used in phishing to create urgency.",
                "severity": "low",
            })

    return issues
