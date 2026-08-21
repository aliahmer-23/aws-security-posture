import unittest

from checks.rds import analyze_rds


class TestRDSSecurity(unittest.TestCase):

    def test_secure_instance_has_zero_findings(self):
        instances = [
            {
                "DBInstanceIdentifier": "secure-db",
                "StorageEncrypted": True,
                "PubliclyAccessible": False,
                "BackupRetentionPeriod": 7,
                "DeletionProtection": True,
            }
        ]

        self.assertEqual(
            analyze_rds(instances),
            [],
        )

    def test_insecure_instance_has_four_findings(self):
        instances = [
            {
                "DBInstanceIdentifier": "app-db",
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "BackupRetentionPeriod": 0,
                "DeletionProtection": False,
            }
        ]

        findings = analyze_rds(instances)

        self.assertEqual(len(findings), 4)

        self.assertEqual(
            {finding.id for finding in findings},
            {
                "ASP-RDS-001",
                "ASP-RDS-002",
                "ASP-RDS-003",
                "ASP-RDS-004",
            },
        )

    def test_public_database_is_high(self):
        findings = analyze_rds(
            [
                {
                    "DBInstanceIdentifier": "public-db",
                    "StorageEncrypted": True,
                    "PubliclyAccessible": True,
                    "BackupRetentionPeriod": 7,
                    "DeletionProtection": True,
                }
            ]
        )

        self.assertEqual(
            findings[0].severity,
            "HIGH",
        )

    def test_resource_contains_identifier(self):
        findings = analyze_rds(
            [
                {
                    "DBInstanceIdentifier": "production-db",
                    "StorageEncrypted": False,
                    "PubliclyAccessible": False,
                    "BackupRetentionPeriod": 7,
                    "DeletionProtection": True,
                }
            ]
        )

        self.assertEqual(
            findings[0].resource,
            "rds:production-db",
        )

    def test_unknown_values_do_not_false_positive(self):
        instances = [
            {
                "DBInstanceIdentifier": "unknown-db",
                "StorageEncrypted": None,
                "PubliclyAccessible": None,
                "BackupRetentionPeriod": None,
                "DeletionProtection": None,
            }
        ]

        self.assertEqual(
            analyze_rds(instances),
            [],
        )


if __name__ == "__main__":
    unittest.main()
