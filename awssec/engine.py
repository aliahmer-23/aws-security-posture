from typing import Dict, Iterable

from awssec.models import Finding


SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}


def calculate_risk(
    findings: Iterable[Finding],
) -> Dict[str, object]:

    findings = list(findings)

    counts = {
        severity.lower(): 0
        for severity in SEVERITY_WEIGHTS
    }

    raw_score = 0

    for finding in findings:
        counts[finding.severity.lower()] += 1
        raw_score += SEVERITY_WEIGHTS[finding.severity]

    risk_score = min(raw_score, 100)

    if risk_score >= 80:
        overall = "CRITICAL"
    elif risk_score >= 40:
        overall = "HIGH"
    elif risk_score >= 20:
        overall = "MEDIUM"
    elif risk_score > 0:
        overall = "LOW"
    else:
        overall = "PASS"

    return {
        "risk_score": risk_score,
        "raw_risk_score": raw_score,
        **counts,
        "total": len(findings),
        "overall_risk": overall,
    }
