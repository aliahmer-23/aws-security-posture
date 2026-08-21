import unittest

from checks.ec2 import (
    analyze_security_group,
    analyze_security_groups,
)


SECURE_GROUP = {
    "GroupId": "sg-secure",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [
                {
                    "CidrIp": "10.0.0.0/16",
                }
            ],
        }
    ],
}


PUBLIC_SSH_GROUP = {
    "GroupId": "sg-public-ssh",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0",
                }
            ],
        }
    ],
}


PUBLIC_RDP_GROUP = {
    "GroupId": "sg-public-rdp",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "Ipv6Ranges": [
                {
                    "CidrIpv6": "::/0",
                }
            ],
        }
    ],
}


OPEN_ALL_GROUP = {
    "GroupId": "sg-open-all",
    "IpPermissions": [
        {
            "IpProtocol": "-1",
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0",
                }
            ],
        }
    ],
}


class TestEC2Security(unittest.TestCase):

    def test_secure_group_has_zero_findings(self):
        findings = analyze_security_group(
            SECURE_GROUP
        )

        self.assertEqual(len(findings), 0)

    def test_public_ssh_detected(self):
        findings = analyze_security_group(
            PUBLIC_SSH_GROUP
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].id,
            "ASP-EC2-001",
        )
        self.assertEqual(
            findings[0].severity,
            "HIGH",
        )

    def test_public_rdp_detected(self):
        findings = analyze_security_group(
            PUBLIC_RDP_GROUP
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-EC2-002",
            ids,
        )

    def test_open_all_detected(self):
        findings = analyze_security_group(
            OPEN_ALL_GROUP
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-EC2-003",
            ids,
        )

    def test_open_all_is_critical(self):
        findings = analyze_security_group(
            OPEN_ALL_GROUP
        )

        finding = next(
            item
            for item in findings
            if item.id == "ASP-EC2-003"
        )

        self.assertEqual(
            finding.severity,
            "CRITICAL",
        )

    def test_ipv6_public_range_detected(self):
        findings = analyze_security_group(
            PUBLIC_RDP_GROUP
        )

        self.assertEqual(
            findings[0].evidence[
                "public_ranges"
            ],
            ["::/0"],
        )

    def test_resource_contains_group_id(self):
        findings = analyze_security_group(
            PUBLIC_SSH_GROUP
        )

        self.assertEqual(
            findings[0].resource,
            "ec2:security-group:sg-public-ssh",
        )

    def test_multiple_groups_analyzed(self):
        findings = analyze_security_groups(
            [
                SECURE_GROUP,
                PUBLIC_SSH_GROUP,
                PUBLIC_RDP_GROUP,
            ]
        )

        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
