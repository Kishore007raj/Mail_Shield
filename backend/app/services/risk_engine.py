import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

MAX_SCORE = 100


def calculate_risk(
    rule_flags: list[dict],
    url_findings: list[dict],
    header_issues: list[dict],
    ml_prediction: dict,
) -> dict:
    """
    Combine all detection signals into a unified risk assessment.

    Returns:
        {
            "risk_score": int (0-100),
            "classification": "Safe" | "Suspicious" | "Phishing",
            "reasons": [str],
            "details": {
                "rule_flags": [...],
                "urls": [...],
                "header_issues": [...],
                "ml_prediction": {...}
            }
        }
    """
    score = 0
    reasons = []

    rule_score = 0
    for flag in rule_flags:
        severity = flag.get("severity", "low")
        weight = SEVERITY_WEIGHTS.get(severity, 3)
        rule_score += weight

    rule_score = min(rule_score, 45)
    score += rule_score

    if rule_flags:
        critical_rules = [f for f in rule_flags if f.get("severity") == "critical"]
        high_rules = [f for f in rule_flags if f.get("severity") == "high"]

        if critical_rules:
            reasons.append(
                f"Critical rule violations detected: {', '.join(f['description'] for f in critical_rules[:3])}"
            )
        if high_rules:
            reasons.append(
                f"High-severity rule flags: {', '.join(f['description'] for f in high_rules[:3])}"
            )
        if len(rule_flags) > len(critical_rules) + len(high_rules):
            remaining = len(rule_flags) - len(critical_rules) - len(high_rules)
            reasons.append(f"{remaining} additional rule-based indicators detected")

    url_score = 0
    for finding in url_findings:
        severity = finding.get("severity", "low")
        weight = SEVERITY_WEIGHTS.get(severity, 3)
        url_score += weight

    url_score = min(url_score, 30)
    score += url_score

    if url_findings:
        critical_urls = [f for f in url_findings if f.get("severity") == "critical"]
        if critical_urls:
            reasons.append(
                f"Dangerous URLs detected: {', '.join(f['description'] for f in critical_urls[:2])}"
            )
        elif url_findings:
            reasons.append(f"{len(url_findings)} suspicious URL(s) detected")

    header_score = 0
    for issue in header_issues:
        severity = issue.get("severity", "low")
        weight = SEVERITY_WEIGHTS.get(severity, 3)
        header_score += weight

    header_score = min(header_score, 35)
    score += header_score

    if header_issues:
        critical_headers = [i for i in header_issues if i.get("severity") == "critical"]
        if critical_headers:
            reasons.append(
                f"Critical header anomalies: {', '.join(i['description'] for i in critical_headers[:2])}"
            )
        elif header_issues:
            reasons.append(f"{len(header_issues)} email header anomaly(ies) detected")

    ml_score = 0
    if ml_prediction.get("available", False):
        prediction = ml_prediction.get("prediction", "").lower()
        confidence = ml_prediction.get("confidence", 0.0)

        if prediction == "phishing":
            ml_score = int(confidence * 20)
            reasons.append(
                f"ML model classified as phishing (confidence: {confidence:.1%})"
            )
        elif prediction == "legitimate":
            ml_score = -int(confidence * 5)
            if confidence > 0.85 and score > 20:
                reasons.append(
                    f"ML model classified as legitimate (confidence: {confidence:.1%}), reducing risk"
                )
    else:
        reasons.append("ML model unavailable — relying on rule-based and forensic analysis")

    score += ml_score
    score = max(0, min(score, MAX_SCORE))

    if score >= 70:
        classification = "Phishing"
    elif score >= 30:
        classification = "Suspicious"
    else:
        classification = "Safe"

    if not reasons:
        reasons.append("No significant phishing indicators detected")

    result = {
        "risk_score": score,
        "classification": classification,
        "reasons": reasons,
        "details": {
            "rule_flags": rule_flags,
            "urls": url_findings,
            "header_issues": header_issues,
            "ml_prediction": ml_prediction,
        }
    }

    logger.info(f"Risk assessment: score={score}, classification={classification}")
    return result
