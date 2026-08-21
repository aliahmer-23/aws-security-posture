import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from collectors.s3_details import collect_s3_security_details


def client_error(code, operation):
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": "Test AWS error",
            }
        },
        operation,
    )


class TestS3SecurityDetails(unittest.TestCase):

    def make_s3(self):
        s3 = MagicMock()

        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }

        s3.get_bucket_versioning.return_value = {
            "Status": "Enabled"
        }

        return s3

    def inventory(self):
        return {
            "Buckets": [
                {"Name": "security-data"}
            ]
        }

    def test_secure_bucket_details_collected(self):
        s3 = self.make_s3()

        result = collect_s3_security_details(
            s3,
            self.inventory(),
        )

        self.assertEqual(len(result), 1)

        bucket = result[0]

        self.assertEqual(
            bucket["name"],
            "security-data",
        )

        self.assertTrue(
            bucket["public_access_block"][
                "BlockPublicAcls"
            ]
        )

        self.assertIsNotNone(
            bucket["encryption"]
        )

        self.assertEqual(
            bucket["versioning"],
            "Enabled",
        )

        self.assertEqual(
            bucket["collection_errors"],
            [],
        )

    def test_missing_public_access_block(self):
        s3 = self.make_s3()

        s3.get_public_access_block.side_effect = client_error(
            "NoSuchPublicAccessBlockConfiguration",
            "GetPublicAccessBlock",
        )

        result = collect_s3_security_details(
            s3,
            self.inventory(),
        )

        self.assertEqual(
            result[0]["public_access_block"],
            {},
        )

        self.assertEqual(
            result[0]["collection_errors"],
            [],
        )

    def test_missing_encryption(self):
        s3 = self.make_s3()

        s3.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError",
            "GetBucketEncryption",
        )

        result = collect_s3_security_details(
            s3,
            self.inventory(),
        )

        self.assertIsNone(
            result[0]["encryption"]
        )

        self.assertEqual(
            result[0]["collection_errors"],
            [],
        )

    def test_public_access_permission_error_recorded(self):
        s3 = self.make_s3()

        s3.get_public_access_block.side_effect = client_error(
            "AccessDenied",
            "GetPublicAccessBlock",
        )

        result = collect_s3_security_details(
            s3,
            self.inventory(),
        )

        bucket = result[0]

        self.assertIsNone(
            bucket["public_access_block"]
        )

        self.assertEqual(
            bucket["collection_errors"][0]["code"],
            "AccessDenied",
        )

    def test_encryption_permission_error_recorded(self):
        s3 = self.make_s3()

        s3.get_bucket_encryption.side_effect = client_error(
            "AccessDenied",
            "GetBucketEncryption",
        )

        result = collect_s3_security_details(
            s3,
            self.inventory(),
        )

        self.assertIsNone(
            result[0]["encryption"]
        )

        self.assertEqual(
            result[0]["collection_errors"][0]["operation"],
            "get_bucket_encryption",
        )

    def test_versioning_permission_error_recorded(self):
        s3 = self.make_s3()

        s3.get_bucket_versioning.side_effect = client_error(
            "AccessDenied",
            "GetBucketVersioning",
        )

        result = collect_s3_security_details(
            s3,
            self.inventory(),
        )

        self.assertIsNone(
            result[0]["versioning"]
        )

        self.assertEqual(
            result[0]["collection_errors"][0]["code"],
            "AccessDenied",
        )

    def test_one_bucket_failure_does_not_abort_collection(self):
        s3 = self.make_s3()

        s3.get_bucket_versioning.side_effect = [
            client_error(
                "AccessDenied",
                "GetBucketVersioning",
            ),
            {"Status": "Enabled"},
        ]

        inventory = {
            "Buckets": [
                {"Name": "restricted-data"},
                {"Name": "security-data"},
            ]
        }

        result = collect_s3_security_details(
            s3,
            inventory,
        )

        self.assertEqual(
            len(result),
            2,
        )

        self.assertEqual(
            result[1]["versioning"],
            "Enabled",
        )


if __name__ == "__main__":
    unittest.main()
