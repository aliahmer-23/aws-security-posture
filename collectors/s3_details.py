from typing import Any, Dict, List

from botocore.exceptions import ClientError


def _error_code(exc: ClientError) -> str:
    """
    Return the AWS error code from a botocore ClientError.
    """

    return (
        exc.response
        .get("Error", {})
        .get("Code", "Unknown")
    )


def collect_s3_security_details(
    s3: Any,
    buckets_response: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Collect read-only security configuration for S3 buckets.

    Missing security configuration is represented as insecure
    configuration.

    Permission/API failures are represented as unknown so the
    scanner does not incorrectly claim that an inaccessible
    configuration is insecure.

    No bucket or object is created, modified, or deleted.
    """

    buckets = []

    for bucket in buckets_response.get("Buckets", []):
        name = bucket.get("Name")

        if not name:
            continue

        errors = []

        # ----------------------------------------------------
        # Public Access Block
        # ----------------------------------------------------

        try:
            response = s3.get_public_access_block(
                Bucket=name
            )

            public_access = response.get(
                "PublicAccessBlockConfiguration",
                {},
            )

        except ClientError as exc:
            code = _error_code(exc)

            if code == "NoSuchPublicAccessBlockConfiguration":
                public_access = {}
            else:
                public_access = None
                errors.append({
                    "operation": "get_public_access_block",
                    "code": code,
                })

        # ----------------------------------------------------
        # Encryption
        # ----------------------------------------------------

        try:
            response = s3.get_bucket_encryption(
                Bucket=name
            )

            rules = response.get(
                "ServerSideEncryptionConfiguration",
                {},
            ).get(
                "Rules",
                [],
            )

            encryption = rules[0] if rules else None

        except ClientError as exc:
            code = _error_code(exc)

            if code == (
                "ServerSideEncryptionConfigurationNotFoundError"
            ):
                encryption = None
            else:
                encryption = None
                errors.append({
                    "operation": "get_bucket_encryption",
                    "code": code,
                })

        # ----------------------------------------------------
        # Versioning
        # ----------------------------------------------------

        try:
            response = s3.get_bucket_versioning(
                Bucket=name
            )

            versioning = response.get("Status")

        except ClientError as exc:
            versioning = None

            errors.append({
                "operation": "get_bucket_versioning",
                "code": _error_code(exc),
            })

        buckets.append({
            "name": name,
            "public_access_block": public_access,
            "encryption": encryption,
            "versioning": versioning,
            "collection_errors": errors,
        })

    return buckets
