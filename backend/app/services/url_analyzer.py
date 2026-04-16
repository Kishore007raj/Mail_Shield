import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

LEGITIMATE_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov", ".mil",
    ".co.uk", ".ac.uk", ".gov.uk",
    ".de", ".fr", ".jp", ".au", ".ca", ".in",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".work", ".buzz",
    ".loan", ".click", ".download", ".stream",
    ".racing", ".review", ".win", ".bid",
}

BRAND_TYPOSQUATS = {
    "paypal": ["paypa1", "paypall", "pay-pal", "paypaI", "peypal", "payp4l", "paypai"],
    "google": ["g00gle", "googIe", "gooogle", "go0gle", "goog1e"],
    "microsoft": ["micros0ft", "mlcrosoft", "micosoft", "microsft", "micr0soft"],
    "apple": ["app1e", "appIe", "aple", "applle"],
    "amazon": ["amaz0n", "arnazon", "arnazon", "amazom", "amzon"],
    "facebook": ["faceb00k", "faceboook", "facebok"],
    "netflix": ["netfIix", "netfl1x", "netfix", "neflix"],
    "chase": ["chas3", "chasse", "cbase"],
    "wellsfargo": ["wells-farg0", "wellsfarg0", "we11sfargo"],
    "bankofamerica": ["bankofamer1ca", "bank0famerica", "bankofarnerica"],
}


def analyze_urls(urls: list[str]) -> list[dict]:
    """
    Analyze a list of URLs for phishing indicators.
    Returns a list of suspicious URL findings.
    """
    findings = []

    for url in urls:
        url_findings = _analyze_single_url(url)
        if url_findings:
            findings.extend(url_findings)

    logger.info(f"URL analyzer found {len(findings)} issues across {len(urls)} URLs")
    return findings


def _analyze_single_url(url: str) -> list[dict]:
    """Analyze a single URL for various phishing indicators."""
    issues = []

    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        issues.append({
            "url": url,
            "issue": "malformed_url",
            "description": "URL could not be parsed - potentially malformed",
            "severity": "medium"
        })
        return issues

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    if _is_ip_based(hostname):
        issues.append({
            "url": url,
            "issue": "ip_based_url",
            "description": f"URL uses raw IP address ({hostname}) instead of domain name",
            "severity": "high"
        })

    typosquat = _detect_typosquatting(hostname)
    if typosquat:
        issues.append({
            "url": url,
            "issue": "typosquatting",
            "description": f"Domain may be impersonating '{typosquat['brand']}' (detected: '{typosquat['match']}')",
            "severity": "critical"
        })

    obfuscation = _detect_obfuscation(url, parsed)
    if obfuscation:
        issues.extend(obfuscation)

    tld_check = _check_suspicious_tld(hostname)
    if tld_check:
        issues.append(tld_check)

    if parsed.scheme == "http" and any(
        kw in path.lower() or kw in query.lower()
        for kw in ["login", "signin", "account", "verify", "secure", "banking", "password"]
    ):
        issues.append({
            "url": url,
            "issue": "insecure_sensitive_page",
            "description": "Sensitive page (login/account) served over insecure HTTP",
            "severity": "high"
        })

    if len(hostname) > 50:
        issues.append({
            "url": url,
            "issue": "excessive_domain_length",
            "description": f"Suspiciously long domain name ({len(hostname)} characters)",
            "severity": "medium"
        })

    subdomain_count = hostname.count(".") - 1
    if subdomain_count >= 3:
        issues.append({
            "url": url,
            "issue": "excessive_subdomains",
            "description": f"Excessive subdomains ({subdomain_count + 1} levels deep)",
            "severity": "medium"
        })

    if "@" in url.split("//")[-1].split("/")[0]:
        issues.append({
            "url": url,
            "issue": "at_sign_in_url",
            "description": "URL contains '@' sign which can disguise the actual destination",
            "severity": "critical"
        })

    return issues


def _is_ip_based(hostname: str) -> bool:
    """Check if hostname is an IP address."""
    ipv4_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
    )
    if ipv4_pattern.match(hostname):
        return True

    hex_ip = re.compile(r'^0x[0-9a-fA-F]+$')
    if hex_ip.match(hostname):
        return True

    return False


def _detect_typosquatting(hostname: str) -> dict | None:
    """Check if domain is a typosquat of a known brand."""
    hostname_lower = hostname.lower().replace("www.", "")

    for brand, variants in BRAND_TYPOSQUATS.items():
        for variant in variants:
            if variant in hostname_lower:
                return {"brand": brand, "match": variant}

    return None


def _detect_obfuscation(url: str, parsed) -> list[dict]:
    """Detect URL obfuscation techniques."""
    issues = []

    hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')
    hex_matches = hex_pattern.findall(url)
    if len(hex_matches) > 3:
        issues.append({
            "url": url,
            "issue": "hex_encoding",
            "description": f"URL contains excessive hex encoding ({len(hex_matches)} encoded characters)",
            "severity": "high"
        })

    if re.search(r'https?://[^/]*https?://', url):
        issues.append({
            "url": url,
            "issue": "url_within_url",
            "description": "URL contains another URL embedded within it",
            "severity": "high"
        })

    shortened_domains = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee",
        "rb.gy", "cutt.ly", "short.io",
    ]
    hostname = (parsed.hostname or "").lower()
    for domain in shortened_domains:
        if hostname == domain or hostname.endswith("." + domain):
            issues.append({
                "url": url,
                "issue": "url_shortener",
                "description": f"URL uses shortener service ({domain}) to hide destination",
                "severity": "medium"
            })

    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        issues.append({
            "url": url,
            "issue": "unusual_port",
            "description": f"URL uses unusual port number ({parsed.port})",
            "severity": "medium"
        })

    return issues


def _check_suspicious_tld(hostname: str) -> dict | None:
    """Check if the domain uses a suspicious TLD."""
    hostname_lower = hostname.lower()

    for tld in SUSPICIOUS_TLDS:
        if hostname_lower.endswith(tld):
            return {
                "url": hostname,
                "issue": "suspicious_tld",
                "description": f"Domain uses suspicious TLD '{tld}' commonly associated with phishing",
                "severity": "medium"
            }

    return None
