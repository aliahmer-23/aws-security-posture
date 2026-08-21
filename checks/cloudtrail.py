from typing import Dict, List

from awssec.models import Finding


def analyze_cloudtrail(
    trails: List[Dict],
) -> List[Finding]:

    findings = []

    if not trails:
        findings.append(
            Finding(
                id="ASP-CT-001",
                severity="HIGH",
                service="CloudTrail",
                resource="cloudtrail:account",
                title="No CloudTrail trail configured",
                observation=(
                    "No CloudTrail trail was detected "
                    "for the assessed account."
                ),
                recommendation=(
                    "Configure CloudTrail to record "
                    "AWS account activity."
                ),
                evidence={
                    "trail_count": 0,
                },
            )
        )

        return findings

    for trail in trails:
        name = trail.get(
            "Name",
            "unknown-trail",
        )

        resource = f"cloudtrail:{name}"

        collection_errors = trail.get(
            "collection_errors",
            [],
        )

        logging_collection_failed = any(
            error.get("operation") == "get_trail_status"
            for error in collection_errors
        )

        if (
            not logging_collection_failed
            and trail.get("IsLogging") is False
        ):
            findings.append(
                Finding(
                    id="ASP-CT-002",
                    severity="HIGH",
                    service="CloudTrail",
                    resource=resource,
                    title="CloudTrail logging disabled",
                    observation=(
                        "The CloudTrail trail is not "
                        "actively logging."
                    ),
                    recommendation=(
                        "Enable logging for the "
                        "CloudTrail trail."
                    ),
                    evidence={
                        "is_logging": False,
                    },
                )
            )

        if not trail.get(
            "LogFileValidationEnabled",
            False,
        ):
            findings.append(
                Finding(
                    id="ASP-CT-003",
                    severity="MEDIUM",
                    service="CloudTrail",
                    resource=resource,
                    title="CloudTrail log validation disabled",
                    observation=(
                        "CloudTrail log-file integrity "
                        "validation is disabled."
                    ),
                    recommendation=(
                        "Enable CloudTrail log-file "
                        "validation."
                    ),
                    evidence={
                        "log_file_validation": False,
                    },
                )
            )

        if not trail.get("MultiRegionTrail", False):
            findings.append(
                Finding(
                    id="ASP-CT-004",
                    severity="MEDIUM",
                    service="CloudTrail",
                    resource=resource,
                    title="CloudTrail is not multi-region",
                    observation=(
                        "The trail is not configured "
                        "as a multi-region trail."
                    ),
                    recommendation=(
                        "Use a multi-region trail to "
                        "improve account-wide visibility."
                    ),
                    evidence={
                        "multi_region": False,
                    },
                )
            )

    return findings
