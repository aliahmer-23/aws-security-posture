import unittest

from awssec.engine import calculate_risk
from awssec.models import Finding


def make_finding(
    severity="HIGH",
    finding_id="ASP-TEST-001",
):
    return Finding(
        id=finding_id,
        severity=severity,
        service="TEST",
        resource="test-resource",
        title="Test security finding",
        observation="Test observation",
        recommendation="Test recommendation",
        evidence={"demo": True},
    )


class TestFindingModel(unittest.TestCase):

    def test_finding_serialization(self):
        finding = make_finding()

        document = finding.to_dict()

        self.assertEqual(
            document["id"],
            "ASP-TEST-001",
        )
        self.assertEqual(
            document["severity"],
            "HIGH",
        )

    def test_severity_normalized(self):
        finding = make_finding(
            severity="medium",
        )

        self.assertEqual(
            finding.severity,
            "MEDIUM",
        )

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            make_finding(
                severity="DANGEROUS",
            )


    def test_known_finding_gets_compliance_mapping(self):
        finding = make_finding(
            finding_id="ASP-IAM-001",
        )

        self.assertEqual(
            finding.compliance[0]["control_id"],
            "IAM.4",
        )
        self.assertEqual(
            finding.compliance[0]["relationship"],
            "DIRECT",
        )

    def test_unknown_finding_has_empty_compliance(self):
        finding = make_finding(
            finding_id="ASP-TEST-001",
        )

        self.assertEqual(
            finding.compliance,
            [],
        )

    def test_compliance_serialized(self):
        finding = make_finding(
            finding_id="ASP-S3-003",
        )

        document = finding.to_dict()

        self.assertEqual(
            document["compliance"][0]["control_id"],
            "S3.14",
        )


class TestRiskEngine(unittest.TestCase):

    def test_zero_findings_pass(self):
        summary = calculate_risk([])

        self.assertEqual(
            summary["risk_score"],
            0,
        )
        self.assertEqual(
            summary["overall_risk"],
            "PASS",
        )

    def test_high_finding_score(self):
        summary = calculate_risk(
            [make_finding("HIGH")]
        )

        self.assertEqual(
            summary["risk_score"],
            10,
        )
        self.assertEqual(
            summary["high"],
            1,
        )

    def test_mixed_risk_calculation(self):
        findings = [
            make_finding("CRITICAL", "TEST-001"),
            make_finding("HIGH", "TEST-002"),
            make_finding("MEDIUM", "TEST-003"),
            make_finding("LOW", "TEST-004"),
        ]

        summary = calculate_risk(findings)

        self.assertEqual(
            summary["raw_risk_score"],
            37,
        )
        self.assertEqual(
            summary["total"],
            4,
        )
        self.assertEqual(
            summary["overall_risk"],
            "MEDIUM",
        )

    def test_risk_score_capped_at_100(self):
        findings = [
            make_finding(
                "CRITICAL",
                f"TEST-{index}",
            )
            for index in range(10)
        ]

        summary = calculate_risk(findings)

        self.assertEqual(
            summary["raw_risk_score"],
            200,
        )
        self.assertEqual(
            summary["risk_score"],
            100,
        )
        self.assertEqual(
            summary["overall_risk"],
            "CRITICAL",
        )


if __name__ == "__main__":
    unittest.main()
