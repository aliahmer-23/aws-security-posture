from typing import Any, Dict, List


SERVICES = (
    "iam",
    "s3",
    "ec2",
    "cloudtrail",
    "rds",
    "kms",
    "vpc",
    "lambda",
)


def _errors_from_items(
    items: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    errors = []

    for item in items:
        errors.extend(
            item.get(
                "collection_errors",
                [],
            )
        )

    return errors


def calculate_coverage(
    environment: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate assessment coverage independently from
    security findings.

    Collection failures must never be interpreted as
    evidence that a service is secure.
    """

    iam = environment.get("iam", {})
    s3 = environment.get("s3", [])
    ec2_errors = environment.get(
        "ec2_collection_errors",
        [],
    )
    cloudtrail = environment.get(
        "cloudtrail",
        [],
    )
    rds_errors = environment.get(
        "rds_collection_errors",
        [],
    )
    kms = environment.get(
        "kms",
        [],
    )
    kms_errors = list(
        environment.get(
            "kms_collection_errors",
            [],
        )
    )
    kms_errors.extend(
        _errors_from_items(kms)
    )

    vpc_errors = environment.get(
        "vpc_collection_errors",
        [],
    )

    lambda_items = environment.get(
        "lambda",
        [],
    )

    lambda_errors = list(
        environment.get(
            "lambda_collection_errors",
            [],
        )
    )

    lambda_errors.extend(
        _errors_from_items(
            lambda_items
        )
    )

    errors = {
        "iam": iam.get(
            "collection_errors",
            [],
        ),
        "s3": _errors_from_items(s3),
        "ec2": ec2_errors,
        "cloudtrail": _errors_from_items(
            cloudtrail
        ),
        "rds": rds_errors,
        "kms": kms_errors,
        "vpc": vpc_errors,
        "lambda": lambda_errors,
    }

    services = {}

    for service in SERVICES:
        service_errors = errors[service]

        services[service] = {
            "status": (
                "PARTIAL"
                if service_errors
                else "COMPLETE"
            ),
            "collection_errors": service_errors,
        }

    complete = sum(
        1
        for service in services.values()
        if service["status"] == "COMPLETE"
    )

    partial = sum(
        1
        for service in services.values()
        if service["status"] == "PARTIAL"
    )

    failed = sum(
        1
        for service in services.values()
        if service["status"] == "FAILED"
    )

    error_count = sum(
        len(service["collection_errors"])
        for service in services.values()
    )

    confidence = (
        "COMPLETE"
        if error_count == 0
        else "PARTIAL"
    )

    return {
        "services": services,
        "services_assessed": len(SERVICES),
        "complete": complete,
        "partial": partial,
        "failed": failed,
        "collection_errors": error_count,
        "confidence": confidence,
    }
