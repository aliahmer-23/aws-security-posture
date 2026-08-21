import unittest
from unittest.mock import Mock

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
