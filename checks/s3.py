from typing import Dict, List

from awssec.models import Finding


def analyze_s3_bucket(
    bucket: Dict,
) -> List[Finding]:

    findings = []

    name = bucket.get("name", "unknown-bucket")
    resource = f"s3://{name}"

    collection_errors = bucket.get(
        "collection_errors",
        [],
    )

    failed_operations = {
        error.get("operation")
        for error in collection_errors
        if error.get("operation")
    }

    public_access = bucket.get(
        "public_access_block",
        {},
    )

    required_public_controls = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )

    disabled_controls = []

    if "get_public_access_block" not in failed_operations:
        disabled_controls = [
            control
            for control in required_public_controls
            if public_access.get(control) is not True
        ]

    if disabled_controls:
        findings.append(
            Finding(
                id="ASP-S3-001",
                severity="HIGH",
                service="S3",
                resource=resource,
                title="S3 public access protection incomplete",
                observation=(
                    "One or more S3 public-access "
                    "protection controls are disabled."
                ),
                recommendation=(
                    "Enable all S3 Block Public Access "
                    "controls for the bucket."
                ),
                evidence={
                    "disabled_controls": disabled_controls,
                },
            )
        )

    encryption = bucket.get("encryption")

    if (
        "get_bucket_encryption" not in failed_operations
        and not encryption
    ):
        findings.append(
            Finding(
                id="ASP-S3-002",
                severity="MEDIUM",
                service="S3",
                resource=resource,
                title="S3 encryption not configured",
                observation=(
                    "No bucket encryption configuration "
                    "was detected."
                ),
                recommendation=(
                    "Configure server-side encryption "
                    "for the S3 bucket."
                ),
                evidence={
                    "encryption": encryption,
                },
            )
        )

    versioning = bucket.get("versioning")

    if (
        "get_bucket_versioning" not in failed_operations
        and versioning != "Enabled"
    ):
        findings.append(
            Finding(
                id="ASP-S3-003",
                severity="LOW",
                service="S3",
                resource=resource,
                title="S3 versioning not enabled",
                observation=(
                    "Bucket versioning is not enabled."
                ),
                recommendation=(
                    "Enable S3 versioning where recovery "
                    "and object history are required."
                ),
                evidence={
                    "versioning": versioning,
                },
            )
        )

    return findings


def analyze_s3(
    buckets: List[Dict],
) -> List[Finding]:

    findings = []

    for bucket in buckets:
        findings.extend(
            analyze_s3_bucket(bucket)
        )

    return findings
