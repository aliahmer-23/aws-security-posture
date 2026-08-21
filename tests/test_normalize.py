import unittest

from collectors.normalize import (
    normalize_cloudtrail,
    normalize_environment,
    normalize_iam,
    normalize_kms,
    normalize_rds,
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
                "rds",
                "kms",
                "vpc",
            },
        )


if __name__ == "__main__":
    unittest.main()


class TestRDSNormalization(unittest.TestCase):

    def test_rds_security_properties_normalized(self):
        response = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "app-db",
                    "StorageEncrypted": True,
                    "PubliclyAccessible": False,
                    "BackupRetentionPeriod": 7,
                    "DeletionProtection": True,
                }
            ]
        }

        result = normalize_rds(response)

        self.assertEqual(
            result[0]["DBInstanceIdentifier"],
            "app-db",
        )
        self.assertTrue(
            result[0]["StorageEncrypted"]
        )
        self.assertFalse(
            result[0]["PubliclyAccessible"]
        )
        self.assertEqual(
            result[0]["BackupRetentionPeriod"],
            7,
        )
        self.assertTrue(
            result[0]["DeletionProtection"]
        )


class TestKMSNormalization(unittest.TestCase):

    def test_kms_security_properties_normalized(self):
        response = {
            "Keys": [
                {
                    "KeyId": "key-123",
                    "KeyArn": "arn:test:key-123",
                    "KeyMetadata": {
                        "Arn": "arn:test:key-123",
                        "KeyManager": "CUSTOMER",
                        "KeyState": "Enabled",
                        "KeySpec": "SYMMETRIC_DEFAULT",
                        "Origin": "AWS_KMS",
                        "MultiRegion": False,
                    },
                    "RotationEnabled": True,
                    "CollectionErrors": [],
                }
            ]
        }

        result = normalize_kms(response)

        self.assertEqual(
            result[0]["KeyId"],
            "key-123",
        )
        self.assertEqual(
            result[0]["KeyManager"],
            "CUSTOMER",
        )
        self.assertEqual(
            result[0]["KeyState"],
            "Enabled",
        )
        self.assertTrue(
            result[0]["RotationEnabled"]
        )
        self.assertEqual(
            result[0]["collection_errors"],
            [],
        )


class TestVPCNormalization(unittest.TestCase):

    def test_vpc_security_normalized(self):
        from collectors.normalize import normalize_vpc

        result = normalize_vpc({
            "Vpcs": [
                {
                    "VpcId": "vpc-123",
                }
            ],
            "FlowLogs": [
                {
                    "ResourceId": "vpc-123",
                }
            ],
            "DefaultSecurityGroups": [
                {
                    "VpcId": "vpc-123",
                    "GroupId": "sg-default",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                }
            ],
        })

        self.assertEqual(
            result[0]["VpcId"],
            "vpc-123",
        )

        self.assertTrue(
            result[0]["FlowLogsEnabled"]
        )

        self.assertEqual(
            result[0][
                "DefaultSecurityGroup"
            ]["GroupId"],
            "sg-default",
        )
