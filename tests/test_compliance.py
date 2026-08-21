import unittest

from awssec.compliance import (
    COMPLIANCE_MAPPINGS,
    DIRECT,
    PARTIAL,
    VALID_RELATIONSHIPS,
    get_compliance_mappings,
)


class TestComplianceMappings(unittest.TestCase):

    def test_known_direct_mapping(self):
        mappings = get_compliance_mappings(
            "ASP-IAM-001"
        )

        self.assertEqual(
            mappings[0]["framework"],
            "AWS Security Hub CSPM",
        )
        self.assertEqual(
            mappings[0]["control_id"],
            "IAM.4",
        )
        self.assertEqual(
            mappings[0]["relationship"],
            DIRECT,
        )

    def test_partial_mapping(self):
        mappings = get_compliance_mappings(
            "ASP-CT-004"
        )

        self.assertEqual(
            mappings[0]["control_id"],
            "CloudTrail.1",
        )
        self.assertEqual(
            mappings[0]["relationship"],
            PARTIAL,
        )

    def test_unknown_finding_returns_empty_list(self):
        self.assertEqual(
            get_compliance_mappings(
                "ASP-UNKNOWN-999"
            ),
            [],
        )

    def test_relationships_are_valid(self):
        for mappings in COMPLIANCE_MAPPINGS.values():
            for mapping in mappings:
                self.assertIn(
                    mapping["relationship"],
                    VALID_RELATIONSHIPS,
                )

    def test_returned_mappings_are_defensive_copies(self):
        mappings = get_compliance_mappings(
            "ASP-IAM-001"
        )

        mappings[0]["control_id"] = "MODIFIED"

        fresh = get_compliance_mappings(
            "ASP-IAM-001"
        )

        self.assertEqual(
            fresh[0]["control_id"],
            "IAM.4",
        )

    def test_rds_compliance_mappings(self):
        expected = {
            "ASP-RDS-001": "RDS.3",
            "ASP-RDS-002": "RDS.2",
            "ASP-RDS-003": "RDS.11",
            "ASP-RDS-004": "RDS.8",
        }

        for finding_id, control_id in expected.items():
            mappings = get_compliance_mappings(finding_id)

            self.assertEqual(len(mappings), 1)
            self.assertEqual(
                mappings[0]["framework"],
                "AWS Security Hub CSPM",
            )
            self.assertEqual(
                mappings[0]["control_id"],
                control_id,
            )
            self.assertEqual(
                mappings[0]["relationship"],
                DIRECT,
            )

    def test_kms_compliance_mapping(self):
        mappings = get_compliance_mappings(
            "ASP-KMS-002"
        )

        self.assertEqual(len(mappings), 1)
        self.assertEqual(
            mappings[0]["control_id"],
            "KMS.4",
        )
        self.assertEqual(
            mappings[0]["relationship"],
            DIRECT,
        )

    def test_lambda_compliance_mapping(self):
        mappings = get_compliance_mappings(
            "ASP-LAMBDA-002"
        )

        self.assertEqual(len(mappings), 1)
        self.assertEqual(
            mappings[0]["control_id"],
            "Lambda.3",
        )
        self.assertEqual(
            mappings[0]["relationship"],
            DIRECT,
        )


if __name__ == "__main__":
    unittest.main()
