from typing import Any, Dict, List


def normalize_iam(
    account_summary: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert IAM get_account_summary() output into the
    normalized format expected by the assessment engine.
    """

    summary = account_summary.get("SummaryMap", {})

    return {
        "root_access_keys": summary.get(
            "AccountAccessKeysPresent",
            0,
        ),
        "root_mfa_enabled": bool(
            summary.get(
                "AccountMFAEnabled",
                0,
            )
        ),
        "unused_access_keys": 0,
        "admin_users": 0,
        "password_policy": {
            "minimum_length": 14,
        },
    }


def normalize_s3(
    list_buckets_response: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Normalize the bucket inventory returned by list_buckets().

    Detailed bucket security settings will be enriched by
    dedicated read-only S3 collection calls later.
    """

    buckets = []

    for bucket in list_buckets_response.get("Buckets", []):
        name = bucket.get("Name")

        if not name:
            continue

        buckets.append({
            "name": name,
            "public_access_block": {},
            "encryption": None,
            "versioning": None,
        })

    return buckets


def normalize_security_groups(
    response: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert EC2 describe_security_groups() output into the
    structure consumed by the EC2 security checks.
    """

    groups = []

    for group in response.get("SecurityGroups", []):
        groups.append({
            "GroupId": group.get(
                "GroupId",
                "unknown",
            ),
            "IpPermissions": group.get(
                "IpPermissions",
                [],
            ),
        })

    return groups


def normalize_cloudtrail(
    response: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Normalize CloudTrail describe_trails() output.

    IsLogging is not provided by describe_trails(), so
    detailed status will be enriched with get_trail_status()
    later.
    """

    trails = []

    for trail in response.get("trailList", []):
        trails.append({
            "Name": trail.get(
                "Name",
                "unknown",
            ),
            "IsLogging": None,
            "LogFileValidationEnabled": trail.get(
                "LogFileValidationEnabled",
                False,
            ),
            "MultiRegionTrail": trail.get(
                "IsMultiRegionTrail",
                False,
            ),
        })

    return trails


def normalize_environment(
    account_summary: Dict[str, Any],
    buckets: Dict[str, Any],
    security_groups: Dict[str, Any],
    trails: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build the normalized AWS environment document consumed
    by run_assessment().
    """

    return {
        "iam": normalize_iam(
            account_summary
        ),
        "s3": normalize_s3(
            buckets
        ),
        "security_groups": normalize_security_groups(
            security_groups
        ),
        "cloudtrail": normalize_cloudtrail(
            trails
        ),
    }
