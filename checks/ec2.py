from typing import Dict, List

from awssec.models import Finding


PUBLIC_CIDRS = {
    "0.0.0.0/0",
    "::/0",
}


def _public_ranges(permission: Dict) -> List[str]:
    ranges = []

    for item in permission.get("IpRanges", []):
        cidr = item.get("CidrIp")

        if cidr in PUBLIC_CIDRS:
            ranges.append(cidr)

    for item in permission.get("Ipv6Ranges", []):
        cidr = item.get("CidrIpv6")

        if cidr in PUBLIC_CIDRS:
            ranges.append(cidr)

    return ranges


def _port_exposed(
    permission: Dict,
    port: int,
) -> bool:

    protocol = str(
        permission.get("IpProtocol", "")
    )

    if protocol == "-1":
        return True

    if protocol not in {"tcp", "6"}:
        return False

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if from_port is None or to_port is None:
        return False

    return from_port <= port <= to_port


def analyze_security_group(
    group: Dict,
) -> List[Finding]:

    findings = []

    group_id = group.get(
        "GroupId",
        "unknown-security-group",
    )

    resource = f"ec2:security-group:{group_id}"

    for permission in group.get(
        "IpPermissions",
        [],
    ):
        public_ranges = _public_ranges(permission)

        if not public_ranges:
            continue

        if _port_exposed(permission, 22):
            findings.append(
                Finding(
                    id="ASP-EC2-001",
                    severity="HIGH",
                    service="EC2",
                    resource=resource,
                    title="SSH exposed to the internet",
                    observation=(
                        "Security group permits public "
                        "inbound access to TCP port 22."
                    ),
                    recommendation=(
                        "Restrict SSH access to approved "
                        "administrative networks."
                    ),
                    evidence={
                        "port": 22,
                        "public_ranges": public_ranges,
                    },
                )
            )

        if _port_exposed(permission, 3389):
            findings.append(
                Finding(
                    id="ASP-EC2-002",
                    severity="HIGH",
                    service="EC2",
                    resource=resource,
                    title="RDP exposed to the internet",
                    observation=(
                        "Security group permits public "
                        "inbound access to TCP port 3389."
                    ),
                    recommendation=(
                        "Restrict RDP access to approved "
                        "administrative networks."
                    ),
                    evidence={
                        "port": 3389,
                        "public_ranges": public_ranges,
                    },
                )
            )

        if str(permission.get("IpProtocol")) == "-1":
            findings.append(
                Finding(
                    id="ASP-EC2-003",
                    severity="CRITICAL",
                    service="EC2",
                    resource=resource,
                    title="All traffic exposed to the internet",
                    observation=(
                        "Security group permits all "
                        "protocols from a public CIDR."
                    ),
                    recommendation=(
                        "Replace unrestricted inbound "
                        "access with least-privilege rules."
                    ),
                    evidence={
                        "protocol": "-1",
                        "public_ranges": public_ranges,
                    },
                )
            )

    return findings


def analyze_security_groups(
    groups: List[Dict],
) -> List[Finding]:

    findings = []

    for group in groups:
        findings.extend(
            analyze_security_group(group)
        )

    return findings
