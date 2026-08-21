from typing import Any, Dict, Optional

from awssec.assessment import run_assessment
from collectors.aws import AWSCollector
from collectors.cloudtrail_details import collect_cloudtrail_status
from collectors.iam_details import collect_iam_security_details
from collectors.normalize import normalize_environment
from collectors.s3_details import collect_s3_security_details
from collectors.session import create_aws_clients


def run_live_assessment(
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Collect read-only AWS security data, normalize it,
    and run the existing posture assessment engine.
    """

    clients = create_aws_clients(
        region=region,
        profile=profile,
    )

    collector = AWSCollector(clients)

    account_summary = collector.collect_account_summary()
    bucket_inventory = collector.collect_s3_buckets()
    security_groups = collector.collect_security_groups()
    trails = collector.collect_trails()

    environment = normalize_environment(
        account_summary=account_summary,
        buckets=bucket_inventory,
        security_groups=security_groups,
        trails=trails,
    )

    environment["iam"] = collect_iam_security_details(
        clients["iam"],
        account_summary,
    )

    environment["s3"] = collect_s3_security_details(
        clients["s3"],
        bucket_inventory,
    )

    environment["cloudtrail"] = collect_cloudtrail_status(
        clients["cloudtrail"],
        trails,
    )

    return run_assessment(environment)
