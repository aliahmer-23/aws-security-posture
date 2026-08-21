import unittest

from awssec.coverage import calculate_coverage


class TestAssessmentCoverage(unittest.TestCase):

    def test_complete_coverage(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [
                {
                    "name": "data",
                    "collection_errors": [],
                }
            ],
            "security_groups": [],
            "ec2_collection_errors": [],
            "cloudtrail": [
                {
                    "Name": "security-trail",
                    "collection_errors": [],
                }
            ],
        }

        coverage = calculate_coverage(
            environment
        )

        self.assertEqual(
            coverage["confidence"],
            "COMPLETE",
        )

        self.assertEqual(
            coverage["complete"],
            7,
        )

        self.assertEqual(
            coverage["collection_errors"],
            0,
        )

    def test_partial_s3_coverage(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [
                {
                    "name": "data",
                    "collection_errors": [
                        {
                            "operation": (
                                "get_bucket_encryption"
                            ),
                            "code": "AccessDenied",
                        }
                    ],
                }
            ],
            "ec2_collection_errors": [],
            "cloudtrail": [],
        }

        coverage = calculate_coverage(
            environment
        )

        self.assertEqual(
            coverage["services"]["s3"]["status"],
            "PARTIAL",
        )

        self.assertEqual(
            coverage["confidence"],
            "PARTIAL",
        )

        self.assertEqual(
            coverage["collection_errors"],
            1,
        )

    def test_ec2_collection_error(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "ec2_collection_errors": [
                {
                    "operation": (
                        "describe_security_groups"
                    ),
                    "code": "AccessDenied",
                }
            ],
            "cloudtrail": [],
        }

        coverage = calculate_coverage(
            environment
        )

        self.assertEqual(
            coverage["services"]["ec2"]["status"],
            "PARTIAL",
        )

        self.assertEqual(
            coverage["confidence"],
            "PARTIAL",
        )


if __name__ == "__main__":
    unittest.main()


class TestCoverageIntegration(unittest.TestCase):

    def test_assessment_preserves_ec2_partial_coverage(self):
        from awssec.assessment import run_assessment

        environment = {
            "iam": {
                "root_access_keys": 0,
                "root_mfa_enabled": True,
                "unused_access_keys": 0,
                "admin_users": 1,
                "password_policy": {
                    "minimum_length": 14,
                },
                "collection_errors": [],
            },
            "s3": [],
            "security_groups": [],
            "ec2_collection_errors": [
                {
                    "operation": (
                        "describe_security_groups"
                    ),
                    "code": "AccessDenied",
                }
            ],
            "cloudtrail": [],
        }

        assessment = run_assessment(
            environment
        )

        coverage = assessment["coverage"]

        self.assertEqual(
            coverage["services"]["ec2"]["status"],
            "PARTIAL",
        )

        self.assertEqual(
            coverage["confidence"],
            "PARTIAL",
        )

        self.assertEqual(
            coverage["collection_errors"],
            1,
        )

    def test_serialization_preserves_coverage(self):
        from awssec.assessment import (
            run_assessment,
            serialize_assessment,
        )

        environment = {
            "iam": {
                "root_access_keys": 0,
                "root_mfa_enabled": True,
                "unused_access_keys": 0,
                "admin_users": 1,
                "password_policy": {
                    "minimum_length": 14,
                },
                "collection_errors": [],
            },
            "s3": [],
            "security_groups": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
        }

        serialized = serialize_assessment(
            run_assessment(environment)
        )

        self.assertIn(
            "coverage",
            serialized,
        )

        self.assertEqual(
            serialized["coverage"]["confidence"],
            "COMPLETE",
        )


class TestRDSCoverage(unittest.TestCase):

    def test_rds_complete_coverage(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
            "rds": [],
            "rds_collection_errors": [],
        }

        coverage = calculate_coverage(environment)

        self.assertEqual(
            coverage["services"]["rds"]["status"],
            "COMPLETE",
        )

        self.assertEqual(
            coverage["services_assessed"],
            7,
        )

    def test_rds_collection_error_is_partial(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
            "rds": [],
            "rds_collection_errors": [
                {
                    "operation": "describe_db_instances",
                    "code": "AccessDenied",
                }
            ],
        }

        coverage = calculate_coverage(environment)

        self.assertEqual(
            coverage["services"]["rds"]["status"],
            "PARTIAL",
        )

        self.assertEqual(
            coverage["confidence"],
            "PARTIAL",
        )


class TestKMSCoverage(unittest.TestCase):

    def test_kms_complete_coverage(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
            "rds": [],
            "rds_collection_errors": [],
            "kms": [],
            "kms_collection_errors": [],
        }

        coverage = calculate_coverage(environment)

        self.assertEqual(
            coverage["services"]["kms"]["status"],
            "COMPLETE",
        )
        self.assertEqual(
            coverage["services_assessed"],
            7,
        )

    def test_kms_collection_error_is_partial(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
            "rds": [],
            "rds_collection_errors": [],
            "kms": [],
            "kms_collection_errors": [
                {
                    "operation": "list_keys",
                    "code": "AccessDenied",
                }
            ],
        }

        coverage = calculate_coverage(environment)

        self.assertEqual(
            coverage["services"]["kms"]["status"],
            "PARTIAL",
        )
        self.assertEqual(
            coverage["confidence"],
            "PARTIAL",
        )

    def test_kms_key_detail_error_is_partial(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "ec2_collection_errors": [],
            "cloudtrail": [],
            "rds": [],
            "rds_collection_errors": [],
            "kms": [
                {
                    "collection_errors": [
                        {
                            "operation": (
                                "get_key_rotation_status"
                            ),
                            "code": "AccessDenied",
                        }
                    ]
                }
            ],
            "kms_collection_errors": [],
        }

        coverage = calculate_coverage(environment)

        self.assertEqual(
            coverage["services"]["kms"]["status"],
            "PARTIAL",
        )


class TestVPCCoverage(unittest.TestCase):

    def test_vpc_complete_coverage(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "security_groups": [],
            "cloudtrail": [],
            "rds": [],
            "kms": [],
            "vpc": [],
            "ec2_collection_errors": [],
            "rds_collection_errors": [],
            "kms_collection_errors": [],
            "vpc_collection_errors": [],
        }

        coverage = calculate_coverage(
            environment
        )

        self.assertEqual(
            coverage["services"]["vpc"]["status"],
            "COMPLETE",
        )

    def test_vpc_collection_error_is_partial(self):
        environment = {
            "iam": {
                "collection_errors": [],
            },
            "s3": [],
            "security_groups": [],
            "cloudtrail": [],
            "rds": [],
            "kms": [],
            "vpc": [],
            "ec2_collection_errors": [],
            "rds_collection_errors": [],
            "kms_collection_errors": [],
            "vpc_collection_errors": [
                {
                    "operation": "describe_flow_logs",
                    "code": "AccessDenied",
                }
            ],
        }

        coverage = calculate_coverage(
            environment
        )

        self.assertEqual(
            coverage["services"]["vpc"]["status"],
            "PARTIAL",
        )
