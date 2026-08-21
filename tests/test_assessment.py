import unittest

from awssec.assessment import (
    run_assessment,
    serialize_assessment,
)


SECURE_ENVIRONMENT = {
    "iam": {
        "root_access_keys": 0,
        "root_mfa_enabled": True,
        "unused_access_keys": 0,
        "admin_users": 1,
        "password_policy": {
            "minimum_length": 14,
        },
    },
    "s3": [
        {
            "name": "secure-data",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "encryption": {
                "algorithm": "AES256",
            },
            "versioning": "Enabled",
        }
    ],
    "security_groups": [
        {
            "GroupId": "sg-secure",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "10.0.0.0/16",
                        }
                    ],
                }
            ],
        }
    ],
    "cloudtrail": [
        {
            "Name": "security-trail",
            "IsLogging": True,
            "LogFileValidationEnabled": True,
            "MultiRegionTrail": True,
        }
    ],
}


INSECURE_ENVIRONMENT = {
    "iam": {
        "root_access_keys": 1,
        "root_mfa_enabled": False,
        "unused_access_keys": 3,
        "admin_users": 4,
        "password_policy": {
            "minimum_length": 8,
        },
    },
    "s3": [
        {
            "name": "public-data",
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "encryption": None,
            "versioning": "Suspended",
        }
    ],
    "security_groups": [
        {
            "GroupId": "sg-public-admin",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
            ],
        }
    ],
    "cloudtrail": [
        {
            "Name": "legacy-trail",
            "IsLogging": False,
            "LogFileValidationEnabled": False,
            "MultiRegionTrail": False,
        }
    ],
}


class TestAssessmentEngine(unittest.TestCase):

    def test_secure_environment_has_zero_findings(self):
        result = run_assessment(
            SECURE_ENVIRONMENT
        )

        self.assertEqual(
            len(result["findings"]),
            0,
        )

    def test_secure_environment_passes(self):
        result = run_assessment(
            SECURE_ENVIRONMENT
        )

        self.assertEqual(
            result["risk"]["overall_risk"],
            "PASS",
        )

    def test_insecure_environment_has_findings(self):
        result = run_assessment(
            INSECURE_ENVIRONMENT
        )

        self.assertGreater(
            len(result["findings"]),
            0,
        )

    def test_insecure_environment_is_critical(self):
        result = run_assessment(
            INSECURE_ENVIRONMENT
        )

        self.assertEqual(
            result["risk"]["overall_risk"],
            "CRITICAL",
        )

    def test_multiple_services_present(self):
        result = run_assessment(
            INSECURE_ENVIRONMENT
        )

        services = {
            finding.service
            for finding in result["findings"]
        }

        self.assertEqual(
            services,
            {
                "IAM",
                "S3",
                "EC2",
                "CloudTrail",
            },
        )

    def test_serialization(self):
        result = serialize_assessment(
            run_assessment(
                INSECURE_ENVIRONMENT
            )
        )

        self.assertIsInstance(
            result["findings"],
            list,
        )

        self.assertIsInstance(
            result["findings"][0],
            dict,
        )

    def test_serialized_risk_present(self):
        result = serialize_assessment(
            run_assessment(
                INSECURE_ENVIRONMENT
            )
        )

        self.assertIn(
            "risk_score",
            result["risk"],
        )


if __name__ == "__main__":
    unittest.main()
