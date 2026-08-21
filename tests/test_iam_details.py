import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from collectors.iam_details import (
    collect_iam_security_details,
)


NOW = datetime(
    2026,
    8,
    21,
    tzinfo=timezone.utc,
)


def client_error(code, operation):
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": "test error",
            }
        },
        operation,
    )


class TestIAMSecurityDetails(unittest.TestCase):

    def base_iam(self):
        iam = MagicMock()

        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 16,
            }
        }

        iam.list_users.return_value = {
            "Users": [
                {"UserName": "security-user"}
            ],
            "IsTruncated": False,
        }

        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": []
        }

        iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": []
        }

        return iam

    def summary(self):
        return {
            "SummaryMap": {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
            }
        }

    def test_root_security_preserved(self):
        iam = self.base_iam()

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertEqual(
            result["root_access_keys"],
            0,
        )

        self.assertTrue(
            result["root_mfa_enabled"]
        )

    def test_password_policy_collected(self):
        iam = self.base_iam()

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertEqual(
            result["password_policy"][
                "minimum_length"
            ],
            16,
        )

    def test_missing_password_policy(self):
        iam = self.base_iam()

        iam.get_account_password_policy.side_effect = (
            client_error(
                "NoSuchEntity",
                "GetAccountPasswordPolicy",
            )
        )

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertEqual(
            result["password_policy"][
                "minimum_length"
            ],
            0,
        )

    def test_old_access_key_detected(self):
        iam = self.base_iam()

        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "TESTKEY",
                    "Status": "Active",
                }
            ]
        }

        iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {
                "LastUsedDate":
                    NOW - timedelta(days=120)
            }
        }

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertEqual(
            result["unused_access_keys"],
            1,
        )

    def test_never_used_access_key_detected(self):
        iam = self.base_iam()

        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "TESTKEY",
                    "Status": "Active",
                }
            ]
        }

        iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {}
        }

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertEqual(
            result["unused_access_keys"],
            1,
        )

    def test_admin_policy_detected(self):
        iam = self.base_iam()

        iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyArn": (
                        "arn:aws:iam::aws:policy/"
                        "AdministratorAccess"
                    )
                }
            ]
        }

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertEqual(
            result["admin_users"],
            1,
        )

    def test_permission_failure_recorded(self):
        iam = self.base_iam()

        iam.get_account_password_policy.side_effect = (
            client_error(
                "AccessDenied",
                "GetAccountPasswordPolicy",
            )
        )

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertIsNone(
            result["password_policy"]
        )

        self.assertEqual(
            result["collection_errors"][0][
                "operation"
            ],
            "get_account_password_policy",
        )

    def test_user_collection_failure_is_unknown(self):
        iam = self.base_iam()

        iam.list_users.side_effect = client_error(
            "AccessDenied",
            "ListUsers",
        )

        result = collect_iam_security_details(
            iam,
            self.summary(),
            now=NOW,
        )

        self.assertIsNone(
            result["unused_access_keys"]
        )

        self.assertIsNone(
            result["admin_users"]
        )


if __name__ == "__main__":
    unittest.main()
