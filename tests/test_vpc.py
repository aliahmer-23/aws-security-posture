import unittest

from checks.vpc import analyze_vpc


SECURE_VPC = {
    "VpcId": "vpc-secure",
    "FlowLogsEnabled": True,
    "DefaultSecurityGroup": {
        "GroupId": "sg-default",
        "IpPermissions": [],
        "IpPermissionsEgress": [],
    },
}


INSECURE_VPC = {
    "VpcId": "vpc-insecure",
    "FlowLogsEnabled": False,
    "DefaultSecurityGroup": {
        "GroupId": "sg-default-insecure",
        "IpPermissions": [
            {
                "IpProtocol": "-1",
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
            }
        ],
    },
}


class TestVPCSecurity(unittest.TestCase):

    def test_secure_vpc_has_zero_findings(self):
        findings = analyze_vpc(
            [SECURE_VPC]
        )

        self.assertEqual(
            len(findings),
            0,
        )

    def test_missing_flow_logs_detected(self):
        findings = analyze_vpc(
            [INSECURE_VPC]
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-VPC-001",
            ids,
        )

    def test_default_group_rules_detected(self):
        findings = analyze_vpc(
            [INSECURE_VPC]
        )

        ids = {
            finding.id
            for finding in findings
        }

        self.assertIn(
            "ASP-VPC-002",
            ids,
        )

    def test_insecure_vpc_has_two_findings(self):
        findings = analyze_vpc(
            [INSECURE_VPC]
        )

        self.assertEqual(
            len(findings),
            2,
        )

    def test_vpc_resource_identifier(self):
        findings = analyze_vpc(
            [INSECURE_VPC]
        )

        flow_log_finding = next(
            finding
            for finding in findings
            if finding.id == "ASP-VPC-001"
        )

        self.assertEqual(
            flow_log_finding.resource,
            "ec2:vpc:vpc-insecure",
        )


if __name__ == "__main__":
    unittest.main()
