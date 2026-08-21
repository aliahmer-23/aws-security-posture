from typing import Any, Dict, List

from botocore.exceptions import ClientError


def collect_cloudtrail_status(
    cloudtrail: Any,
    trails_response: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Collect read-only CloudTrail logging status.

    Collection failures are recorded separately so that
    unavailable AWS data is not interpreted as an insecure
    configuration.
    """

    trails = []

    for trail in trails_response.get("trailList", []):
        name = trail.get("Name")

        if not name:
            continue

        errors = []
        is_logging = None

        try:
            status = cloudtrail.get_trail_status(
                Name=name
            )

            is_logging = status.get(
                "IsLogging"
            )

        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )

            errors.append({
                "operation": "get_trail_status",
                "code": error.get(
                    "Code",
                    "Unknown",
                ),
            })

        trails.append({
            "Name": name,
            "IsLogging": is_logging,
            "LogFileValidationEnabled": trail.get(
                "LogFileValidationEnabled",
                False,
            ),
            "MultiRegionTrail": trail.get(
                "IsMultiRegionTrail",
                False,
            ),
            "collection_errors": errors,
        })

    return trails
