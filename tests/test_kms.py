import unittest

from checks.kms import analyze_kms


class TestKMSSecurity(unittest.TestCase):

    def test_secure_customer_key_has_zero_findings(self):
        keys = [
            {
                "KeyId": "secure-key",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "RotationEnabled": True,
            }
        ]

        self.assertEqual(
            analyze_kms(keys),
            [],
        )

    def test_rotation_disabled_detected(self):
        findings = analyze_kms(
            [
                {
                    "KeyId": "application-key",
                    "KeyManager": "CUSTOMER",
                    "KeyState": "Enabled",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "RotationEnabled": False,
                }
            ]
        )

        self.assertEqual(
            len(findings),
            1,
        )
        self.assertEqual(
            findings[0].id,
            "ASP-KMS-002",
        )
        self.assertEqual(
            findings[0].severity,
            "MEDIUM",
        )

    def test_pending_deletion_detected(self):
        findings = analyze_kms(
            [
                {
                    "KeyId": "important-key",
                    "KeyManager": "CUSTOMER",
                    "KeyState": "PendingDeletion",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "RotationEnabled": None,
                }
            ]
        )

        self.assertEqual(
            len(findings),
            1,
        )
        self.assertEqual(
            findings[0].id,
            "ASP-KMS-001",
        )
        self.assertEqual(
            findings[0].severity,
            "HIGH",
        )

    def test_aws_managed_key_not_flagged(self):
        keys = [
            {
                "KeyId": "aws-managed-key",
                "KeyManager": "AWS",
                "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "RotationEnabled": False,
            }
        ]

        self.assertEqual(
            analyze_kms(keys),
            [],
        )

    def test_unknown_rotation_does_not_false_positive(self):
        keys = [
            {
                "KeyId": "unknown-key",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "RotationEnabled": None,
            }
        ]

        self.assertEqual(
            analyze_kms(keys),
            [],
        )

    def test_asymmetric_key_rotation_not_flagged(self):
        keys = [
            {
                "KeyId": "rsa-key",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeySpec": "RSA_2048",
                "RotationEnabled": False,
            }
        ]

        self.assertEqual(
            analyze_kms(keys),
            [],
        )


if __name__ == "__main__":
    unittest.main()
