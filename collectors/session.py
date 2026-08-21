from typing import Any, Dict, Optional


AWS_SERVICES = (
    "iam",
    "s3",
    "ec2",
    "cloudtrail",
    "rds",
)


def create_aws_clients(
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create boto3 clients used by the security scanner.

    Creating clients does not create or modify AWS resources.
    Credentials are resolved through boto3's standard
    credential provider chain.
    """

    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError(
            "boto3 is required for live AWS scanning. "
            "Install dependencies with: "
            "python3 -m pip install -r requirements.txt"
        ) from exc

    session_kwargs = {}

    if profile:
        session_kwargs["profile_name"] = profile

    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)

    client_kwargs = {}

    if region:
        client_kwargs["region_name"] = region

    return {
        service: session.client(
            service,
            **client_kwargs,
        )
        for service in AWS_SERVICES
    }
