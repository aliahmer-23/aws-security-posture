import unittest
from unittest.mock import MagicMock, patch

from collectors.live import run_live_assessment


class TestLiveAssessment(unittest.TestCase):

    @patch("collectors.live.create_aws_clients")
    def test_live_pipeline_runs_with_mocked_aws(
        self,
        create_clients,
    ):
        iam = MagicMock()
        s3 = MagicMock()
        ec2 = MagicMock()
        cloudtrail = MagicMock()
        rds = MagicMock()
        kms = MagicMock()

        create_clients.return_value = {
            "iam": iam,
            "s3": s3,
            "ec2": ec2,
            "cloudtrail": cloudtrail,
            "rds": rds,
            "kms": kms,
        }

        iam.list_users.return_value = {
            "Users": [],
            "IsTruncated": False,
        }

        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
            }
        }

        iam.get_account_summary.return_value = {
            "SummaryMap": {
                "AccountAccessKeysPresent": 0,
                "AccountMFAEnabled": 1,
            }
        }

        s3.list_buckets.return_value = {
            "Buckets": []
        }

        ec2.describe_security_groups.return_value = {
            "SecurityGroups": []
        }

        ec2.describe_vpcs.return_value = {
            "Vpcs": []
        }

        ec2.describe_flow_logs.return_value = {
            "FlowLogs": []
        }

        cloudtrail.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "security-trail",
                    "LogFileValidationEnabled": True,
                    "IsMultiRegionTrail": True,
                }
            ]
        }

        rds.describe_db_instances.return_value = {
            "DBInstances": []
        }

        kms.list_keys.return_value = {
            "Keys": [],
            "Truncated": False,
        }

        result = run_live_assessment(
            region="us-east-1"
        )

        create_clients.assert_called_once_with(
            region="us-east-1",
            profile=None,
        )

        iam.get_account_summary.assert_called_once_with()
        s3.list_buckets.assert_called_once_with()
        self.assertEqual(
            ec2.describe_security_groups.call_count,
            2,
        )

        ec2.describe_security_groups.assert_any_call()

        ec2.describe_security_groups.assert_any_call(
            Filters=[
                {
                    "Name": "group-name",
                    "Values": ["default"],
                }
            ]
        )
        rds.describe_db_instances.assert_called_once_with()
        kms.list_keys.assert_called_once_with()

        cloudtrail.describe_trails.assert_called_once_with(
            includeShadowTrails=False
        )

        self.assertIn("findings", result)
        self.assertIn("risk", result)

    @patch("collectors.live.create_aws_clients")
    def test_region_and_profile_forwarded(
        self,
        create_clients,
    ):
        iam = MagicMock()
        s3 = MagicMock()
        ec2 = MagicMock()
        cloudtrail = MagicMock()
        rds = MagicMock()
        kms = MagicMock()

        create_clients.return_value = {
            "iam": iam,
            "s3": s3,
            "ec2": ec2,
            "cloudtrail": cloudtrail,
            "rds": rds,
            "kms": kms,
        }

        iam.list_users.return_value = {
            "Users": [],
            "IsTruncated": False,
        }

        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
            }
        }

        iam.get_account_summary.return_value = {
            "SummaryMap": {}
        }

        s3.list_buckets.return_value = {
            "Buckets": []
        }

        ec2.describe_security_groups.return_value = {
            "SecurityGroups": []
        }

        ec2.describe_vpcs.return_value = {
            "Vpcs": []
        }

        ec2.describe_flow_logs.return_value = {
            "FlowLogs": []
        }

        cloudtrail.describe_trails.return_value = {
            "trailList": []
        }

        rds.describe_db_instances.return_value = {
            "DBInstances": []
        }

        kms.list_keys.return_value = {
            "Keys": [],
            "Truncated": False,
        }

        run_live_assessment(
            region="us-east-1",
            profile="security-audit",
        )

        create_clients.assert_called_once_with(
            region="us-east-1",
            profile="security-audit",
        )


if __name__ == "__main__":
    unittest.main()
