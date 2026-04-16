import re
import email
import logging
from email import policy
from email.parser import BytesParser, Parser
from typing import Optional

logger = logging.getLogger(__name__)


class ParsedEmail:
    """Container for parsed email data."""

    def __init__(self):
        self.subject: str = ""
        self.sender: str = ""
        self.receiver: str = ""
        self.reply_to: str = ""
        self.body: str = ""
        self.urls: list[str] = []
        self.headers: dict[str, str] = {}
        self.raw_headers: str = ""
        self.return_path: str = ""
        self.received_chain: list[str] = []
        self.message_id: str = ""
        self.date: str = ""
        self.content_type: str = ""
        self.x_mailer: str = ""
        self.authentication_results: str = ""
        self.dkim_signature: str = ""
        self.spf_result: str = ""


def extract_urls(text: str) -> list[str]:
    """Extract all URLs from text content."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|'
        r'www\.[^\s<>"{}|\\^`\[\]]+|'
        r'ftp://[^\s<>"{}|\\^`\[\]]+'
    )
    urls = url_pattern.findall(text)
    cleaned = []
    for url in urls:
        url = url.rstrip(".,;:!?)'\"]}>")
        if url and len(url) > 5:
            cleaned.append(url)
    return list(set(cleaned))


def extract_body(msg: email.message.Message) -> str:
    """Extract the body content from an email message."""
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                continue

            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
                except Exception as e:
                    logger.warning(f"Failed to decode email part: {e}")
                    continue

            elif content_type == "text/html" and not body_parts:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_text = payload.decode(charset, errors="replace")
                        plain = re.sub(r'<[^>]+>', ' ', html_text)
                        plain = re.sub(r'\s+', ' ', plain).strip()
                        body_parts.append(plain)
                except Exception as e:
                    logger.warning(f"Failed to decode HTML part: {e}")
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    text = re.sub(r'<[^>]+>', ' ', text)
                    text = re.sub(r'\s+', ' ', text).strip()
                body_parts.append(text)
        except Exception as e:
            logger.warning(f"Failed to decode email body: {e}")
            body_parts.append(str(msg.get_payload()))

    return "\n".join(body_parts) if body_parts else ""


def parse_raw_email(raw_text: str) -> ParsedEmail:
    """Parse a raw email string into structured data."""
    parsed = ParsedEmail()

    try:
        msg = email.message_from_string(raw_text, policy=policy.default)
    except Exception as e:
        logger.error(f"Failed to parse raw email: {e}")
        parsed.body = raw_text
        parsed.urls = extract_urls(raw_text)
        return parsed

    parsed.subject = str(msg.get("Subject", ""))
    parsed.sender = str(msg.get("From", ""))
    parsed.receiver = str(msg.get("To", ""))
    parsed.reply_to = str(msg.get("Reply-To", ""))
    parsed.return_path = str(msg.get("Return-Path", ""))
    parsed.message_id = str(msg.get("Message-ID", ""))
    parsed.date = str(msg.get("Date", ""))
    parsed.content_type = str(msg.get("Content-Type", ""))
    parsed.x_mailer = str(msg.get("X-Mailer", ""))
    parsed.authentication_results = str(msg.get("Authentication-Results", ""))
    parsed.dkim_signature = str(msg.get("DKIM-Signature", ""))

    received_headers = msg.get_all("Received", [])
    parsed.received_chain = [str(r) for r in received_headers] if received_headers else []

    for key in msg.keys():
        parsed.headers[key] = str(msg[key])

    header_lines = []
    for key, value in parsed.headers.items():
        header_lines.append(f"{key}: {value}")
    parsed.raw_headers = "\n".join(header_lines)

    parsed.body = extract_body(msg)
    parsed.urls = extract_urls(parsed.body)

    subject_urls = extract_urls(parsed.subject)
    parsed.urls = list(set(parsed.urls + subject_urls))

    return parsed


def parse_eml_file(file_bytes: bytes) -> ParsedEmail:
    """Parse an .eml file (bytes) into structured data."""
    parsed = ParsedEmail()

    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    except Exception as e:
        logger.error(f"Failed to parse .eml file: {e}")
        try:
            raw_text = file_bytes.decode("utf-8", errors="replace")
            return parse_raw_email(raw_text)
        except Exception:
            parsed.body = file_bytes.decode("utf-8", errors="replace")
            parsed.urls = extract_urls(parsed.body)
            return parsed

    parsed.subject = str(msg.get("Subject", ""))
    parsed.sender = str(msg.get("From", ""))
    parsed.receiver = str(msg.get("To", ""))
    parsed.reply_to = str(msg.get("Reply-To", ""))
    parsed.return_path = str(msg.get("Return-Path", ""))
    parsed.message_id = str(msg.get("Message-ID", ""))
    parsed.date = str(msg.get("Date", ""))
    parsed.content_type = str(msg.get("Content-Type", ""))
    parsed.x_mailer = str(msg.get("X-Mailer", ""))
    parsed.authentication_results = str(msg.get("Authentication-Results", ""))
    parsed.dkim_signature = str(msg.get("DKIM-Signature", ""))

    received_headers = msg.get_all("Received", [])
    parsed.received_chain = [str(r) for r in received_headers] if received_headers else []

    for key in msg.keys():
        parsed.headers[key] = str(msg[key])

    header_lines = []
    for key, value in parsed.headers.items():
        header_lines.append(f"{key}: {value}")
    parsed.raw_headers = "\n".join(header_lines)

    parsed.body = extract_body(msg)
    parsed.urls = extract_urls(parsed.body)

    subject_urls = extract_urls(parsed.subject)
    parsed.urls = list(set(parsed.urls + subject_urls))

    return parsed
