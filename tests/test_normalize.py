import unittest

from collectors.normalize import (
    normalize_cloudtrail,
    normalize_environment,
    normalize_iam,
    normalize_s3,
    normalize_security_groups,
)


class TestAWSNormalization(unittest.TestCase):

    def test_iam_root_security_normalized(self):
        response = {
            "SummaryMap": {
                "AccountAccessKeysPresent": 1,
                "AccountMFAEnabled": 0,
            }
        }

        result = normalize_iam(response)

        self.assertEqual(
            result["root_access_keys"],
            1,
        )
        self.assertFalse(
            result["root_mfa_enabled"]
        )

    def test_secure_iam_root_normalized(self):
        response = {
            "SummaryMap": {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
            }
        }

        result = normalize_iam(response)

        self.assertEqual(
            result["root_access_keys"],
            0,
        )
        self.assertTrue(
            result["root_mfa_enabled"]
        )

    def test_s3_bucket_names_normalized(self):
        response = {
            "Buckets": [
                {"Name": "security-data"},
                {"Name": "audit-logs"},
            ]
        }

        result = normalize_s3(response)

        self.assertEqual(len(result), 2)
        self.assertEqual(
            result[0]["name"],
            "security-data",
        )
        self.assertEqual(
            result[1]["name"],
            "audit-logs",
        )

    def test_security_groups_normalized(self):
        permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
            }
        ]

        response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-example",
                    "IpPermissions": permissions,
                }
            ]
        }

        result = normalize_security_groups(
            response
        )

        self.assertEqual(
            result[0]["GroupId"],
            "sg-example",
        )
        self.assertEqual(
            result[0]["IpPermissions"],
            permissions,
        )

    def test_cloudtrail_normalized(self):
        response = {
            "trailList": [
                {
                    "Name": "audit-trail",
                    "LogFileValidationEnabled": True,
                    "IsMultiRegionTrail": True,
                }
            ]
        }

        result = normalize_cloudtrail(response)

        self.assertEqual(
            result[0]["Name"],
            "audit-trail",
        )
        self.assertTrue(
            result[0][
                "LogFileValidationEnabled"
            ]
        )
        self.assertTrue(
            result[0]["MultiRegionTrail"]
        )

    def test_environment_contains_all_services(self):
        result = normalize_environment(
            {
                "SummaryMap": {
                    "AccountAccessKeysPresent": 0,
                    "AccountMFAEnabled": 1,
                }
            },
            {"Buckets": []},
            {"SecurityGroups": []},
            {"trailList": []},
        )

        self.assertEqual(
            set(result),
            {
                "iam",
                "s3",
                "security_groups",
                "cloudtrail",
            },
        )


if __name__ == "__main__":
    unittest.main()
