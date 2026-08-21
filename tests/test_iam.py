import unittest

from checks.iam import analyze_iam


SECURE_ACCOUNT = {
    "root_access_keys": 0,
    "root_mfa_enabled": True,
    "unused_access_keys": 0,
    "admin_users": 1,
    "password_policy": {
        "minimum_length": 14,
    },
}


INSECURE_ACCOUNT = {
    "root_access_keys": 1,
    "root_mfa_enabled": False,
    "unused_access_keys": 3,
    "admin_users": 4,
    "password_policy": {
        "minimum_length": 8,
    },
}


class TestIAMSecurity(unittest.TestCase):

    def test_secure_account_has_zero_findings(self):
        findings = analyze_iam(SECURE_ACCOUNT)
        self.assertEqual(len(findings), 0)

    def test_insecure_account_has_five_findings(self):
        findings = analyze_iam(INSECURE_ACCOUNT)
        self.assertEqual(len(findings), 5)

    def test_root_access_key_detected(self):
        ids = {
            finding.id
            for finding in analyze_iam(INSECURE_ACCOUNT)
        }

        self.assertIn("ASP-IAM-001", ids)

    def test_root_access_key_is_critical(self):
        finding = next(
            item
            for item in analyze_iam(INSECURE_ACCOUNT)
            if item.id == "ASP-IAM-001"
        )

        self.assertEqual(
            finding.severity,
            "CRITICAL",
        )

    def test_missing_root_mfa_detected(self):
        ids = {
            finding.id
            for finding in analyze_iam(INSECURE_ACCOUNT)
        }

        self.assertIn("ASP-IAM-002", ids)

    def test_unused_credentials_detected(self):
        ids = {
            finding.id
            for finding in analyze_iam(INSECURE_ACCOUNT)
        }

        self.assertIn("ASP-IAM-003", ids)

    def test_admin_users_detected(self):
        ids = {
            finding.id
            for finding in analyze_iam(INSECURE_ACCOUNT)
        }

        self.assertIn("ASP-IAM-004", ids)

    def test_weak_password_policy_detected(self):
        ids = {
            finding.id
            for finding in analyze_iam(INSECURE_ACCOUNT)
        }

        self.assertIn("ASP-IAM-005", ids)

    def test_evidence_contains_counts(self):
        findings = analyze_iam(INSECURE_ACCOUNT)

        root = next(
            item
            for item in findings
            if item.id == "ASP-IAM-001"
        )

        self.assertEqual(
            root.evidence["root_access_keys"],
            1,
        )

    def test_iam_service_name(self):
        findings = analyze_iam(INSECURE_ACCOUNT)

        for finding in findings:
            self.assertEqual(
                finding.service,
                "IAM",
            )


class TestIAMCollectionErrors(unittest.TestCase):

    def test_unknown_unused_keys_not_false_positive(self):
        account = {
            "root_access_keys": 0,
            "root_mfa_enabled": True,
            "unused_access_keys": None,
            "admin_users": 1,
            "password_policy": {
                "minimum_length": 14,
            },
        }

        ids = {
            finding.id
            for finding in analyze_iam(account)
        }

        self.assertNotIn(
            "ASP-IAM-003",
            ids,
        )

    def test_unknown_admin_users_not_false_positive(self):
        account = {
            "root_access_keys": 0,
            "root_mfa_enabled": True,
            "unused_access_keys": 0,
            "admin_users": None,
            "password_policy": {
                "minimum_length": 14,
            },
        }

        ids = {
            finding.id
            for finding in analyze_iam(account)
        }

        self.assertNotIn(
            "ASP-IAM-004",
            ids,
        )

    def test_unknown_password_policy_not_false_positive(self):
        account = {
            "root_access_keys": 0,
            "root_mfa_enabled": True,
            "unused_access_keys": 0,
            "admin_users": 1,
            "password_policy": None,
        }

        ids = {
            finding.id
            for finding in analyze_iam(account)
        }

        self.assertNotIn(
            "ASP-IAM-005",
            ids,
        )

    def test_known_insecure_values_still_detected(self):
        account = {
            "root_access_keys": 0,
            "root_mfa_enabled": True,
            "unused_access_keys": 2,
            "admin_users": 3,
            "password_policy": {
                "minimum_length": 8,
            },
        }

        ids = {
            finding.id
            for finding in analyze_iam(account)
        }

        self.assertIn("ASP-IAM-003", ids)
        self.assertIn("ASP-IAM-004", ids)
        self.assertIn("ASP-IAM-005", ids)


if __name__ == "__main__":
    unittest.main()
