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


if __name__ == "__main__":
    unittest.main()
