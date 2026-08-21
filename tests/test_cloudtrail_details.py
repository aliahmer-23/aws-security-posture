import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from collectors.cloudtrail_details import (
    collect_cloudtrail_status,
)


class TestCloudTrailDetails(unittest.TestCase):

    def test_logging_status_collected(self):
        cloudtrail = MagicMock()

        cloudtrail.get_trail_status.return_value = {
            "IsLogging": True
        }

        result = collect_cloudtrail_status(
            cloudtrail,
            {
                "trailList": [
                    {
                        "Name": "security-trail",
                        "LogFileValidationEnabled": True,
                        "IsMultiRegionTrail": True,
                    }
                ]
            },
        )

        self.assertEqual(len(result), 1)
        self.assertTrue(
            result[0]["IsLogging"]
        )

        self.assertEqual(
            result[0]["collection_errors"],
            [],
        )

        cloudtrail.get_trail_status.assert_called_once_with(
            Name="security-trail"
        )

    def test_disabled_logging_collected(self):
        cloudtrail = MagicMock()

        cloudtrail.get_trail_status.return_value = {
            "IsLogging": False
        }

        result = collect_cloudtrail_status(
            cloudtrail,
            {
                "trailList": [
                    {
                        "Name": "legacy-trail",
                        "LogFileValidationEnabled": True,
                        "IsMultiRegionTrail": True,
                    }
                ]
            },
        )

        self.assertFalse(
            result[0]["IsLogging"]
        )

    def test_permission_error_recorded(self):
        cloudtrail = MagicMock()

        cloudtrail.get_trail_status.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access denied",
                }
            },
            "GetTrailStatus",
        )

        result = collect_cloudtrail_status(
            cloudtrail,
            {
                "trailList": [
                    {
                        "Name": "security-trail",
                        "LogFileValidationEnabled": True,
                        "IsMultiRegionTrail": True,
                    }
                ]
            },
        )

        trail = result[0]

        self.assertIsNone(
            trail["IsLogging"]
        )

        self.assertEqual(
            trail["collection_errors"][0]["operation"],
            "get_trail_status",
        )

        self.assertEqual(
            trail["collection_errors"][0]["code"],
            "AccessDeniedException",
        )

    def test_one_failure_does_not_abort_other_trails(self):
        cloudtrail = MagicMock()

        error = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access denied",
                }
            },
            "GetTrailStatus",
        )

        cloudtrail.get_trail_status.side_effect = [
            error,
            {"IsLogging": True},
        ]

        result = collect_cloudtrail_status(
            cloudtrail,
            {
                "trailList": [
                    {"Name": "trail-one"},
                    {"Name": "trail-two"},
                ]
            },
        )

        self.assertEqual(len(result), 2)

        self.assertIsNone(
            result[0]["IsLogging"]
        )

        self.assertTrue(
            result[1]["IsLogging"]
        )


if __name__ == "__main__":
    unittest.main()
