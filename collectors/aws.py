from typing import Any, Dict

from botocore.exceptions import ClientError


class AWSCollector:
    """
    Base AWS security data collector.

    Clients are injected rather than created internally.
    This makes collectors testable and allows the project
    to operate against mocked AWS responses.
    """

    def __init__(self, clients: Dict[str, Any]):
        self.clients = clients

    def _client(self, service: str):
        if service not in self.clients:
            raise ValueError(
                f"AWS client not configured: {service}"
            )

        return self.clients[service]

    def collect_account_summary(self) -> Dict[str, Any]:
        iam = self._client("iam")
        return iam.get_account_summary()

    def collect_s3_buckets(self) -> Dict[str, Any]:
        s3 = self._client("s3")
        return s3.list_buckets()

    def collect_security_groups(self) -> Dict[str, Any]:
        """
        Collect all EC2 security groups using read-only
        describe_security_groups() pagination.

        Collection failures are recorded separately so an
        AWS permission error is not treated as evidence that
        the environment is secure or insecure.
        """

        ec2 = self._client("ec2")

        groups = []
        next_token = None

        try:
            while True:
                kwargs = {}

                if next_token:
                    kwargs["NextToken"] = next_token

                response = ec2.describe_security_groups(
                    **kwargs
                )

                groups.extend(
                    response.get(
                        "SecurityGroups",
                        [],
                    )
                )

                next_token = response.get(
                    "NextToken"
                )

                if not next_token:
                    break

        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )

            return {
                "SecurityGroups": groups,
                "CollectionErrors": [
                    {
                        "operation": (
                            "describe_security_groups"
                        ),
                        "code": error.get(
                            "Code",
                            "Unknown",
                        ),
                    }
                ],
            }

        return {
            "SecurityGroups": groups,
            "CollectionErrors": [],
        }

    def collect_trails(self) -> Dict[str, Any]:
        cloudtrail = self._client("cloudtrail")
        return cloudtrail.describe_trails(
            includeShadowTrails=False
        )