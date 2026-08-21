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


    def collect_vpc_security(self) -> Dict[str, Any]:
        """
        Collect VPCs, VPC Flow Logs, and default security
        groups using read-only EC2 APIs.

        Collection failures are preserved separately so
        incomplete AWS permissions cannot be interpreted as
        a secure result.
        """

        ec2 = self._client("ec2")

        vpcs = []
        flow_logs = []
        default_groups = []
        errors = []

        try:
            response = ec2.describe_vpcs()
            vpcs = response.get(
                "Vpcs",
                [],
            )
        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )
            errors.append({
                "operation": "describe_vpcs",
                "code": error.get(
                    "Code",
                    "Unknown",
                ),
            })

        try:
            response = ec2.describe_flow_logs()
            flow_logs = response.get(
                "FlowLogs",
                [],
            )
        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )
            errors.append({
                "operation": "describe_flow_logs",
                "code": error.get(
                    "Code",
                    "Unknown",
                ),
            })

        try:
            response = ec2.describe_security_groups(
                Filters=[
                    {
                        "Name": "group-name",
                        "Values": ["default"],
                    }
                ]
            )

            default_groups = response.get(
                "SecurityGroups",
                [],
            )

        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )
            errors.append({
                "operation": (
                    "describe_security_groups_default"
                ),
                "code": error.get(
                    "Code",
                    "Unknown",
                ),
            })

        return {
            "Vpcs": vpcs,
            "FlowLogs": flow_logs,
            "DefaultSecurityGroups": default_groups,
            "CollectionErrors": errors,
        }


    def collect_rds_instances(self) -> Dict[str, Any]:
        """
        Collect RDS DB instances using the read-only
        describe_db_instances() API with pagination.

        Collection errors are preserved separately so a
        permission failure cannot be interpreted as a
        secure assessment result.
        """

        rds = self._client("rds")

        instances = []
        marker = None

        try:
            while True:
                kwargs = {}

                if marker:
                    kwargs["Marker"] = marker

                response = rds.describe_db_instances(
                    **kwargs
                )

                instances.extend(
                    response.get(
                        "DBInstances",
                        [],
                    )
                )

                marker = response.get("Marker")

                if not marker:
                    break

        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )

            return {
                "DBInstances": instances,
                "CollectionErrors": [
                    {
                        "operation": (
                            "describe_db_instances"
                        ),
                        "code": error.get(
                            "Code",
                            "Unknown",
                        ),
                    }
                ],
            }

        return {
            "DBInstances": instances,
            "CollectionErrors": [],
        }


    def collect_kms_keys(self) -> Dict[str, Any]:
        """
        Collect customer-visible KMS keys and rotation status
        using read-only KMS APIs.

        Collection failures are recorded separately so
        incomplete permissions cannot be interpreted as a
        secure configuration.
        """

        kms = self._client("kms")

        keys = []
        errors = []
        marker = None

        try:
            while True:
                kwargs = {}

                if marker:
                    kwargs["Marker"] = marker

                response = kms.list_keys(**kwargs)

                for key in response.get("Keys", []):
                    key_id = key.get("KeyId")

                    if not key_id:
                        continue

                    record = {
                        "KeyId": key_id,
                        "KeyArn": key.get("KeyArn"),
                        "KeyMetadata": None,
                        "RotationEnabled": None,
                        "CollectionErrors": [],
                    }

                    try:
                        description = kms.describe_key(
                            KeyId=key_id
                        )

                        record["KeyMetadata"] = (
                            description.get(
                                "KeyMetadata",
                                {},
                            )
                        )

                    except ClientError as exc:
                        error = exc.response.get(
                            "Error",
                            {},
                        )

                        record["CollectionErrors"].append(
                            {
                                "operation": "describe_key",
                                "code": error.get(
                                    "Code",
                                    "Unknown",
                                ),
                            }
                        )

                    metadata = (
                        record.get("KeyMetadata") or {}
                    )

                    manager = metadata.get("KeyManager")
                    state = metadata.get("KeyState")
                    key_spec = metadata.get("KeySpec")

                    rotation_supported = (
                        manager == "CUSTOMER"
                        and state == "Enabled"
                        and key_spec
                        in (
                            None,
                            "SYMMETRIC_DEFAULT",
                        )
                    )

                    if rotation_supported:
                        try:
                            rotation = (
                                kms.get_key_rotation_status(
                                    KeyId=key_id
                                )
                            )

                            record["RotationEnabled"] = (
                                rotation.get(
                                    "KeyRotationEnabled"
                                )
                            )

                        except ClientError as exc:
                            error = exc.response.get(
                                "Error",
                                {},
                            )

                            record[
                                "CollectionErrors"
                            ].append(
                                {
                                    "operation": (
                                        "get_key_rotation_status"
                                    ),
                                    "code": error.get(
                                        "Code",
                                        "Unknown",
                                    ),
                                }
                            )

                    keys.append(record)

                marker = response.get("NextMarker")

                if not response.get("Truncated"):
                    break

                if not marker:
                    break

        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )

            errors.append(
                {
                    "operation": "list_keys",
                    "code": error.get(
                        "Code",
                        "Unknown",
                    ),
                }
            )

        return {
            "Keys": keys,
            "CollectionErrors": errors,
        }

    def collect_lambda_functions(self) -> Dict[str, Any]:
        """
        Collect AWS Lambda function security configuration
        using read-only Lambda APIs.

        Collection failures are preserved separately so
        incomplete permissions cannot be interpreted as a
        secure assessment result.
        """

        lambda_client = self._client("lambda")

        functions = []
        errors = []
        marker = None

        try:
            while True:
                kwargs = {}

                if marker:
                    kwargs["Marker"] = marker

                response = lambda_client.list_functions(
                    **kwargs
                )

                for function in response.get(
                    "Functions",
                    [],
                ):
                    name = function.get("FunctionName")

                    record = dict(function)
                    record["CollectionErrors"] = []

                    if name:
                        try:
                            config = (
                                lambda_client.get_function_configuration(
                                    FunctionName=name
                                )
                            )
                            record.update(config)

                        except ClientError as exc:
                            error = exc.response.get(
                                "Error",
                                {},
                            )

                            record[
                                "CollectionErrors"
                            ].append(
                                {
                                    "operation": (
                                        "get_function_configuration"
                                    ),
                                    "code": error.get(
                                        "Code",
                                        "Unknown",
                                    ),
                                }
                            )

                    functions.append(record)

                marker = response.get("NextMarker")

                if not marker:
                    break

        except ClientError as exc:
            error = exc.response.get(
                "Error",
                {},
            )

            errors.append(
                {
                    "operation": "list_functions",
                    "code": error.get(
                        "Code",
                        "Unknown",
                    ),
                }
            )

        return {
            "Functions": functions,
            "CollectionErrors": errors,
        }


    def collect_trails(self) -> Dict[str, Any]:
        cloudtrail = self._client("cloudtrail")
        return cloudtrail.describe_trails(
            includeShadowTrails=False
        )