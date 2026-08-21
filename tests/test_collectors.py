import unittest
from unittest.mock import Mock
from unittest.mock import MagicMock

from collectors.aws import AWSCollector


class TestAWSCollector(unittest.TestCase):

    def setUp(self):
        self.iam = Mock()
        self.s3 = Mock()
        self.ec2 = Mock()
        self.cloudtrail = Mock()

        self.collector = AWSCollector(
            {
                "iam": self.iam,
                "s3": self.s3,
                "ec2": self.ec2,
                "cloudtrail": self.cloudtrail,
            }
        )

    def test_account_summary_collected(self):
        self.iam.get_account_summary.return_value = {
            "SummaryMap": {
                "Users": 5,
                "Groups": 2,
            }
        }

        result = self.collector.collect_account_summary()

        self.assertEqual(
            result["SummaryMap"]["Users"],
            5,
        )

        self.iam.get_account_summary.assert_called_once_with()

    def test_s3_buckets_collected(self):
        self.s3.list_buckets.return_value = {
            "Buckets": [
                {"Name": "example-private-bucket"},
            ]
        }

        result = self.collector.collect_s3_buckets()

        self.assertEqual(
            len(result["Buckets"]),
            1,
        )

        self.s3.list_buckets.assert_called_once_with()

    def test_security_groups_collected(self):
        self.ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-demo",
                    "GroupName": "demo-security-group",
                }
            ]
        }

        result = self.collector.collect_security_groups()

        self.assertEqual(
            result["SecurityGroups"][0]["GroupId"],
            "sg-demo",
        )

        self.ec2.describe_security_groups.assert_called_once_with()

    def test_cloudtrail_collected(self):
        self.cloudtrail.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "security-audit-trail",
                }
            ]
        }

        result = self.collector.collect_trails()

        self.assertEqual(
            result["trailList"][0]["Name"],
            "security-audit-trail",
        )

        self.cloudtrail.describe_trails.assert_called_once_with(
            includeShadowTrails=False
        )

    def test_missing_client_rejected(self):
        collector = AWSCollector({})

        with self.assertRaises(ValueError):
            collector.collect_s3_buckets()


if __name__ == "__main__":
    unittest.main()


class TestEC2Pagination(unittest.TestCase):

    def test_security_group_pagination(self):
        ec2 = MagicMock()

        ec2.describe_security_groups.side_effect = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-first",
                        "IpPermissions": [],
                    }
                ],
                "NextToken": "page-two",
            },
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-second",
                        "IpPermissions": [],
                    }
                ],
            },
        ]

        collector = AWSCollector(
            {
                "ec2": ec2,
            }
        )

        result = collector.collect_security_groups()

        self.assertEqual(
            len(result["SecurityGroups"]),
            2,
        )

        self.assertEqual(
            result["SecurityGroups"][0]["GroupId"],
            "sg-first",
        )

        self.assertEqual(
            result["SecurityGroups"][1]["GroupId"],
            "sg-second",
        )

        self.assertEqual(
            ec2.describe_security_groups.call_count,
            2,
        )

        ec2.describe_security_groups.assert_any_call()

        ec2.describe_security_groups.assert_any_call(
            NextToken="page-two"
        )


class TestEC2CollectionErrors(unittest.TestCase):

    def test_access_denied_is_recorded(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()

        ec2.describe_security_groups.side_effect = (
            ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "Denied",
                    }
                },
                "DescribeSecurityGroups",
            )
        )

        collector = AWSCollector(
            {
                "ec2": ec2,
            }
        )

        result = collector.collect_security_groups()

        self.assertEqual(
            result["SecurityGroups"],
            [],
        )

        self.assertEqual(
            len(result["CollectionErrors"]),
            1,
        )

        self.assertEqual(
            result["CollectionErrors"][0]["operation"],
            "describe_security_groups",
        )

        self.assertEqual(
            result["CollectionErrors"][0]["code"],
            "AccessDenied",
        )

    def test_success_has_no_collection_errors(self):
        ec2 = MagicMock()

        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [],
        }

        collector = AWSCollector(
            {
                "ec2": ec2,
            }
        )

        result = collector.collect_security_groups()

        self.assertEqual(
            result["CollectionErrors"],
            [],
        )

    def test_partial_pagination_failure_preserves_data(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()

        ec2.describe_security_groups.side_effect = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-first",
                        "IpPermissions": [],
                    }
                ],
                "NextToken": "page-two",
            },
            ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "Denied",
                    }
                },
                "DescribeSecurityGroups",
            ),
        ]

        collector = AWSCollector(
            {
                "ec2": ec2,
            }
        )

        result = collector.collect_security_groups()

        self.assertEqual(
            len(result["SecurityGroups"]),
            1,
        )

        self.assertEqual(
            result["SecurityGroups"][0]["GroupId"],
            "sg-first",
        )

        self.assertEqual(
            result["CollectionErrors"][0]["code"],
            "AccessDenied",
        )


class TestRDSCollection(unittest.TestCase):

    def test_rds_instances_collected(self):
        rds = MagicMock()

        rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "app-db",
                }
            ]
        }

        collector = AWSCollector(
            {
                "rds": rds,
            }
        )

        result = collector.collect_rds_instances()

        self.assertEqual(
            result["DBInstances"][0][
                "DBInstanceIdentifier"
            ],
            "app-db",
        )

        self.assertEqual(
            result["CollectionErrors"],
            [],
        )

    def test_rds_pagination(self):
        rds = MagicMock()

        rds.describe_db_instances.side_effect = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "db-one",
                    }
                ],
                "Marker": "page-two",
            },
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "db-two",
                    }
                ],
            },
        ]

        collector = AWSCollector(
            {
                "rds": rds,
            }
        )

        result = collector.collect_rds_instances()

        self.assertEqual(
            len(result["DBInstances"]),
            2,
        )

        rds.describe_db_instances.assert_any_call()
        rds.describe_db_instances.assert_any_call(
            Marker="page-two"
        )

    def test_rds_access_denied_recorded(self):
        from botocore.exceptions import ClientError

        rds = MagicMock()

        rds.describe_db_instances.side_effect = (
            ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "Denied",
                    }
                },
                "DescribeDBInstances",
            )
        )

        collector = AWSCollector(
            {
                "rds": rds,
            }
        )

        result = collector.collect_rds_instances()

        self.assertEqual(
            result["DBInstances"],
            [],
        )

        self.assertEqual(
            result["CollectionErrors"][0]["code"],
            "AccessDenied",
        )
