from typing import Any, Dict, List

from awssec.models import Finding


def analyze_vpc(
    vpcs: List[Dict[str, Any]],
) -> List[Finding]:
    """Analyze normalized VPC security posture."""

    findings: List[Finding] = []

    for vpc in vpcs:
        vpc_id = vpc.get(
            "VpcId",
            "unknown-vpc",
        )

        resource = f"ec2:vpc:{vpc_id}"

        flow_logs_enabled = vpc.get(
            "FlowLogsEnabled"
        )

        if flow_logs_enabled is False:
            findings.append(
                Finding(
                    id="ASP-VPC-001",
                    severity="MEDIUM",
                    service="VPC",
                    resource=resource,
                    title="VPC Flow Logs not enabled",
                    observation=(
                        "No VPC Flow Log was detected for "
                        "this VPC."
                    ),
                    recommendation=(
                        "Enable VPC Flow Logs for appropriate "
                        "traffic visibility and send logs to "
                        "an approved CloudWatch Logs or S3 "
                        "destination with suitable retention "
                        "and access controls."
                    ),
                    evidence={
                        "vpc_id": vpc_id,
                        "flow_logs_enabled": False,
                    },
                )
            )

        default_group = vpc.get(
            "DefaultSecurityGroup"
        )

        if default_group:
            ingress = default_group.get(
                "IpPermissions",
                [],
            )
            egress = default_group.get(
                "IpPermissionsEgress",
                [],
            )

            if ingress or egress:
                findings.append(
                    Finding(
                        id="ASP-VPC-002",
                        severity="MEDIUM",
                        service="VPC",
                        resource=(
                            "ec2:security-group:"
                            + str(
                                default_group.get(
                                    "GroupId",
                                    "unknown",
                                )
                            )
                        ),
                        title=(
                            "Default security group contains "
                            "active rules"
                        ),
                        observation=(
                            "The default security group for "
                            "the VPC contains ingress or "
                            "egress rules."
                        ),
                        recommendation=(
                            "Remove rules from the default "
                            "security group and use dedicated "
                            "least-privilege security groups "
                            "for workload access."
                        ),
                        evidence={
                            "vpc_id": vpc_id,
                            "group_id": default_group.get(
                                "GroupId"
                            ),
                            "ingress_rule_count": len(
                                ingress
                            ),
                            "egress_rule_count": len(
                                egress
                            ),
                        },
                    )
                )

    return findings
