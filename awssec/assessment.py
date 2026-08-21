from typing import Any, Dict, List

from awssec.engine import calculate_risk
from awssec.models import Finding
from checks.cloudtrail import analyze_cloudtrail
from checks.ec2 import analyze_security_groups
from checks.iam import analyze_iam
from checks.s3 import analyze_s3


def run_assessment(
    environment: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run all supported AWS posture checks against a normalized
    environment document.

    This function performs analysis only. It does not connect
    to AWS or modify infrastructure.
    """

    findings: List[Finding] = []

    findings.extend(
        analyze_iam(
            environment.get("iam", {})
        )
    )

    findings.extend(
        analyze_s3(
            environment.get("s3", [])
        )
    )

    findings.extend(
        analyze_security_groups(
            environment.get(
                "security_groups",
                [],
            )
        )
    )

    findings.extend(
        analyze_cloudtrail(
            environment.get(
                "cloudtrail",
                [],
            )
        )
    )

    risk = calculate_risk(findings)

    return {
        "findings": findings,
        "risk": risk,
    }


def serialize_assessment(
    assessment: Dict[str, Any],
) -> Dict[str, Any]:

    return {
        "risk": assessment["risk"],
        "findings": [
            finding.to_dict()
            for finding in assessment["findings"]
        ],
    }
